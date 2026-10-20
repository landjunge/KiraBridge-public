"""One isolated automatic acceptance: two serial real Codex tasks, simulated Grok.

No installed operator configuration is read. No model retries, resume or nested
agents. The CLI refuses an existing directory; STOP blocks subsequent dispatch.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import shutil
import socket
import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn

from kirabridge.audit_manager import verify
from kirabridge.bridge_core.bridge import Bridge
from kirabridge.bridge_core.config import AgentConfig, Config, PrincipalConfig
from kirabridge.mcp_gateway.client import MCPClientPool, Peer
from kirabridge.mcp_gateway.http import create_http_app
from kirabridge.review_demo import PROMPT, REVIEW, sha


@asynccontextmanager
async def isolated_http(bridge):
    """Own a random loopback socket; never touch the installed service."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(32)
    port = sock.getsockname()[1]
    bridge.config.port = port
    server = uvicorn.Server(
        uvicorn.Config(
            create_http_app(bridge),
            log_level="critical",
            access_log=False,
        )
    )
    async with bridge:
        task = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            async with asyncio.timeout(10):
                while not server.started:
                    if task.done():
                        await task
                        raise RuntimeError("Demo server exited before readiness")
                    await asyncio.sleep(0.02)
            yield f"http://127.0.0.1:{port}/mcp"
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 10)
            sock.close()


def validate_evidence(root, data):
    """Reject missing/mismatched artifacts and cross-linked success claims."""
    root = Path(root)
    first, second = data["tasks"]
    work, review, reply, result = data["messages"]
    sessions = [task["result"]["evidence"]["session_id"] for task in (first, second)]
    result_body = json.loads(result["body"])
    conditions = [
        all(
            task["state"] == "completed"
            and task["result"]["success"]
            and task["result"]["evidence"]["turn_completed"]
            and task["result"]["evidence"]["exit_code"] == 0
            and task["result"]["evidence"]["adapter"] == "codex"
            for task in (first, second)
        ),
        bool(sessions[0]) and bool(sessions[1]) and sessions[0] != sessions[1],
        second["parent_id"] == first["id"],
        first["finished"] <= second["created"],
        review["task_id"] == first["id"] == reply["task_id"],
        reply["reply_to"] == review["id"] and reply["body"] == REVIEW,
        reply["acknowledged"] <= second["created"],
        REVIEW in second["args"]["prompt"],
        result["reply_to"] == work["id"],
        result_body["initial_task_id"] == first["id"],
        result_body["rework_task_id"] == second["id"],
        result_body["review_reply_id"] == reply["id"],
        all(m["receipt"] and m["acknowledged"] for m in data["messages"]),
        sha(root / "initial.html") == data["initial_sha256"],
        sha(root / "site/index.html")
        == data["final_sha256"]
        == data["browser"]["page_sha256"]
        == result_body["sha256"],
        data["initial_sha256"] != data["final_sha256"],
        data["browser"]["passed"] is True and data["audit"]["valid"] is True,
    ]
    if not all(conditions):
        raise RuntimeError("Acceptance evidence correlation failed")


class AutomaticDemo:
    def __init__(self, root, codex, browser_script, *, timeout=180, model=None):
        self.root = Path(root).absolute()
        self.site = self.root / "site"
        self.codex = str(Path(codex).resolve(strict=True))
        self.browser_script = Path(browser_script).resolve(strict=True)
        self.timeout = timeout
        self.model = model
        self.data = {
            "phase": "new",
            "grok": "SIMULATION: deterministic prepared response",
            "chatgpt_connector_verified": False,
            "tasks": [],
            "messages": [],
            "events": [],
            "automatic_retries": 0,
        }
        self.pool = None
        self.bridge = None

    def save(self):
        temp = self.root / "evidence.json.tmp"
        temp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2) + "\n")
        temp.replace(self.root / "evidence.json")

    def log(self, phase, **fields):
        entry = {"at": time.time(), "phase": phase, **fields}
        print(json.dumps(entry, ensure_ascii=False), flush=True)
        self.data["events"].append(entry)
        self.save()

    def check_stop(self):
        if (self.root / "STOP").exists():
            raise RuntimeError("operator_stop")

    async def call(self, identity, tool, **arguments):
        result = await self.pool.call(identity, tool, arguments)
        value = result.structuredContent
        if (
            result.isError
            or not isinstance(value, dict)
            or (value.get("error") and "state" not in value)
        ):
            raise RuntimeError(f"MCP {tool} rejected: {value}")
        return value

    async def send(self, sender, recipient, conversation, key, body, **extra):
        self.check_stop()
        message = {
            "recipient": recipient,
            "conversation_id": conversation,
            "idempotency_key": key,
            "body": body,
            "dispatch": False,
            **extra,
        }
        value = await self.call(sender, "message_send", message=message)
        self.data["messages"].append(value)
        self.log("message_sent", message_id=value["id"], sender=sender, recipient=recipient)
        return value

    async def receive(self, identity, conversation, expected_id):
        value = await self.call(identity, "message_receive", conversation_id=conversation)
        messages = value["messages"]
        if len(messages) != 1 or messages[0]["id"] != expected_id:
            raise RuntimeError("Message correlation failed")
        message = messages[0]
        await self.call(
            identity, "message_ack", message_id=message["id"], receipt=message["receipt"]
        )
        self.log("message_received", message_id=message["id"], recipient=identity)
        return message

    async def cancel_owned(self, task_id):
        """Stop only our exact queued task or our own Bridge process group."""
        current = await self.call("codex", "task_get", task_id=task_id)
        if current["state"] in {"created", "queued"}:
            await self.call("codex", "task_cancel", task_id=task_id)
        elif current["state"] in {"accepted", "running"}:
            request = {
                "task_id": "stop-" + task_id,
                "idempotency_key": "stop-" + task_id,
                "operation": "process.terminate",
                "arguments": {"task_id": task_id},
            }
            await self.call("codex", "task_request", request=request)
        self.log("owned_stop_requested", task_id=task_id)

    async def turn(self, task_id, prompt, parent=None):
        self.check_stop()
        request = {
            "task_id": task_id,
            "idempotency_key": task_id,
            "operation": "agent.execute",
            "arguments": {
                "agent": "codex",
                "prompt": prompt,
                "cwd": str(self.site),
                "timeout": self.timeout,
            },
            "parent_id": parent,
        }
        queued = await self.call("codex", "task_request", request=request)
        self.log("codex_queued", task_id=task_id, state=queued["state"])
        last = None
        try:
            async with asyncio.timeout(self.timeout + 20):
                while True:
                    self.check_stop()
                    task = await self.call("codex", "task_get", task_id=task_id)
                    if task["state"] != last:
                        self.log("codex_state", task_id=task_id, state=task["state"])
                        last = task["state"]
                    if task["state"] in {"completed", "failed", "cancelled", "unknown", "blocked"}:
                        break
                    await asyncio.sleep(0.5)
        except BaseException:
            await self.cancel_owned(task_id)
            raise
        self.data["tasks"].append(task)
        self.data.setdefault("task_events", {})[task_id] = await self.call(
            "codex", "task_events", task_id=task_id
        )
        self.save()
        evidence = (task.get("result") or {}).get("evidence", {})
        if (
            task["state"] != "completed"
            or not evidence.get("turn_completed")
            or evidence.get("exit_code") != 0
            or not evidence.get("session_id")
        ):
            raise RuntimeError(f"Codex execution not confirmed: {task_id} {task['state']}")
        self.log("codex_completed", task_id=task_id, session_id=evidence["session_id"])
        return task

    async def browser(self):
        self.check_stop()
        output = self.root / "browser"
        process = await asyncio.create_subprocess_exec(
            shutil.which("node") or "node",
            str(self.browser_script),
            str(self.site / "index.html"),
            str(output),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 90)
        except BaseException:
            process.kill()
            await process.wait()
            raise
        (self.root / "browser-output.txt").write_bytes(stdout + stderr)
        report = json.loads((output / "browser-checks.json").read_text())
        self.data["browser"] = report
        self.save()
        if (
            process.returncode
            or not report.get("passed")
            or report["page_sha256"] != sha(self.site / "index.html")
        ):
            raise RuntimeError("Browser acceptance failed; see browser-output.txt")
        self.log("browser_passed", checks=report["checks"], version=report["browser_version"])

    async def workflow(self):
        request = await self.send("user", "codex", "work", "user-work", PROMPT, kind="work")
        incoming = await self.receive("codex", "work", request["id"])
        # Intentionally a basic first version; review adds persistence/accessibility.
        first = await self.turn(
            "codex-initial",
            incoming["body"] + "\n"
            "Schreibe nur index.html: eigenständig, deutsch, inline CSS/JS, keine externen "
            "Ressourcen. Verwende einen nativen button mit id=theme und type=button, "
            "html lang=de und data-theme=light/dark. Zunächst nur einfacher Themenwechsel; "
            "Persistenz und aria-pressed folgen im separaten Review. Keine Agenten starten, "
            "kein MCP, kein Netzwerk, keine Dateien außerhalb dieses Verzeichnisses ändern. "
            "Keine Rückfragen. Antworte kurz nach dem tatsächlichen Schreiben.",
        )
        page = self.site / "index.html"
        self.data["initial_sha256"] = sha(page)
        shutil.copyfile(page, self.root / "initial.html")
        review = await self.send(
            "codex",
            "grok-sim",
            "review",
            "review-work",
            "SIMULATION: Prüfe Auftrag " + request["id"] + "; Artefakt SHA256=" + sha(page),
            kind="work",
            task_id=first["id"],
        )
        received = await self.receive("grok-sim", "review", review["id"])
        reply = await self.send(
            "grok-sim",
            "codex",
            "review",
            "review-answer",
            REVIEW,
            kind="answer",
            reply_to=received["id"],
        )
        delivered = await self.receive("codex", "review", reply["id"])
        second = await self.turn(
            "codex-rework",
            "Bearbeite die bestehende index.html. "
            "Die folgende vorbereitete Prüfantwort kam durch KiraBridge, ausdrücklich "
            "SIMULATION. Setze sie tatsächlich um:\n" + delivered["body"] + "\n"
            "Bei gesperrtem localStorage muss der Schalter weiter funktionieren. "
            "Behalte id=theme, type=button und data-theme=light/dark. "
            "Keine Agenten, kein MCP, kein Netzwerk, keine externen Ressourcen. "
            "Nur index.html in diesem Verzeichnis bearbeiten, keine Rückfragen.",
            parent=first["id"],
        )
        self.data["rework_reply_id"] = delivered["id"]
        self.data["final_sha256"] = sha(page)
        if self.data["initial_sha256"] == self.data["final_sha256"]:
            raise RuntimeError("No actual rework artifact change")
        await self.browser()
        self.check_stop()
        result = await self.send(
            "codex",
            "user",
            "work",
            "final-result",
            json.dumps(
                {
                    "page": "site/index.html",
                    "sha256": sha(page),
                    "initial_task_id": first["id"],
                    "rework_task_id": second["id"],
                    "review_reply_id": reply["id"],
                    "browser_passed": True,
                    "grok": "SIMULATION",
                },
                ensure_ascii=False,
            ),
            kind="result",
            reply_to=request["id"],
        )
        await self.receive("user", "work", result["id"])
        # Read the authoritative messages, receipts and events back from MCP.
        archived = []
        for item in self.data["messages"]:
            archived.append(await self.call(item["sender"], "message_get", message_id=item["id"]))
        self.data["messages"] = archived
        self.data["message_events"] = [
            await self.call(item["sender"], "message_events", message_id=item["id"])
            for item in archived
        ]
        self.data["audit"] = verify(self.bridge.store)
        if not self.data["audit"]["valid"] or not all(m["acknowledged"] for m in archived):
            raise RuntimeError("Audit/receipt verification failed")
        validate_evidence(self.root, self.data)
        self.data.update(
            phase="completed", codex_cli_run_verified=True, automatic_workflow_verified=True
        )
        self.log(
            "completed",
            tasks=len(self.data["tasks"]),
            messages=len(archived),
            final_sha256=sha(page),
            audit_valid=True,
        )

    async def run(self):
        self.root.mkdir(mode=0o700)  # exclusive run; never reuse/overwrite evidence
        self.site.mkdir()
        (self.site / "AGENTS.md").write_text(
            "# Isolated acceptance workspace\nEdit only index.html here. "
            "Do not start agents or access network/MCP. Do not modify project files elsewhere.\n"
        )
        self.save()
        tokens = {identity: secrets.token_hex(32) for identity in ["user", "codex", "grok-sim"]}
        names = {identity: "KIRABRIDGE_DEMO_" + secrets.token_hex(8).upper() for identity in tokens}
        for identity in tokens:
            os.environ[names[identity]] = tokens[identity]
        config = Config(
            data_dir=str(self.root / "state"),
            concurrency=1,
            agents={
                "codex": AgentConfig(
                    kind="codex",
                    executable=self.codex,
                    sandbox_mode="workspace-write",
                    model=self.model,
                )
            },
            principals={},
        )
        for identity, peers in [
            ("user", ["codex"]),
            ("codex", ["user", "grok-sim"]),
            ("grok-sim", ["codex"]),
        ]:
            config.principals[identity] = PrincipalConfig(
                approval_mode="automatic",
                token_env=names[identity],
                message_peers=peers,
                roots=[str(self.site)],
                agents=["codex"] if identity == "codex" else [],
                capabilities=["message.send", "message.read", "message.ack"]
                + (
                    ["agent.execute", "task.read", "task.cancel", "process.terminate"]
                    if identity == "codex"
                    else []
                ),
            )
        self.bridge = Bridge(config)
        try:
            async with (
                isolated_http(self.bridge) as endpoint,
                MCPClientPool(call_timeout=15) as pool,
            ):
                self.pool = pool
                for identity, token in tokens.items():
                    await pool.connect(Peer(identity, url=endpoint, token=token))
                self.log(
                    "ready",
                    endpoint="isolated authenticated loopback MCP",
                    codex_executable=self.codex,
                    max_codex_turns=2,
                    timeout_per_turn=self.timeout,
                )
                await self.workflow()
        except BaseException as exc:
            self.data["phase"] = "stopped" if str(exc) == "operator_stop" else "failed"
            self.log(self.data["phase"], error_type=type(exc).__name__, reason=str(exc))
            raise
        finally:
            for name in names.values():
                os.environ.pop(name, None)
        return self.data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--codex", required=True, type=Path)
    parser.add_argument("--model")
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument(
        "--browser-script",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "examples/review-demo/check-browser.cjs",
    )
    args = parser.parse_args()
    if not 5 <= args.timeout <= 300:
        parser.error("timeout must be between 5 and 300 seconds")
    asyncio.run(
        AutomaticDemo(
            args.root, args.codex, args.browser_script, timeout=args.timeout, model=args.model
        ).run()
    )


if __name__ == "__main__":
    main()
