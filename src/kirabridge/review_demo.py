"""Isolated, staged acceptance using real MCP; never launches an agent/provider.

The current Codex operator performs the two edits between stages. This deliberately
cannot attest a new CLI run or a ChatGPT connector invocation.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path

from kirabridge.mcp_gateway.client import MCPClientPool, Peer

REVIEW = (
    "SIMULATION – vorbereitete Grok-Prüfung, kein Provideraufruf: "
    "Ergänze am Hell-Dunkel-Schalter aria-pressed passend zum Zustand und "
    "speichere die Auswahl unter kirabridge-theme in localStorage. "
    "Beim Neuladen muss die Auswahl wiederhergestellt werden."
)
PROMPT = "Erstelle eine kleine deutsche Webseite mit funktionierendem Hell-Dunkel-Schalter."


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Demo:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.config = self.root / "policy.toml"
        self.record = self.root / "evidence.json"

    async def call(self, identity, tool, **arguments):
        async with MCPClientPool(call_timeout=15) as pool:
            await pool.connect(
                Peer(
                    identity,
                    command=sys.executable,
                    args=(
                        "-m",
                        "kirabridge.cli",
                        "--config",
                        str(self.config),
                        "--principal",
                        identity,
                        "serve",
                    ),
                )
            )
            result = await pool.call(identity, tool, arguments)
            value = result.structuredContent
            if result.isError or not isinstance(value, dict) or "error" in value:
                raise RuntimeError(f"MCP {tool} failed: {value}")
            return value

    async def send(self, sender, recipient, conversation, key, body, **extra):
        return await self.call(
            sender,
            "message_send",
            message={
                "recipient": recipient,
                "conversation_id": conversation,
                "idempotency_key": key,
                "body": body,
                "dispatch": False,
                **extra,
            },
        )

    async def receive(self, identity, conversation):
        messages = (
            await self.call(
                identity,
                "message_receive",
                conversation_id=conversation,
            )
        )["messages"]
        if len(messages) != 1:
            raise RuntimeError("Expected exactly one outstanding message")
        return await self.call(
            identity, "message_ack", message_id=messages[0]["id"], receipt=messages[0]["receipt"]
        )

    def save(self, data):
        self.record.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")

    async def run(self, stage):
        if stage == "start":
            self.root.mkdir(mode=0o700)  # refuse overwrite/reuse of any existing demo
            state = json.dumps(str(self.root / "state"))
            policy = f"data_dir = {state}\n[agents]\n"
            for identity, peers in [
                ("user", ["codex"]),
                ("codex", ["user", "grok-sim"]),
                ("grok-sim", ["codex"]),
            ]:
                policy += (
                    f"[principals.{identity}]\napproval_mode = 'automatic'\n"
                    "capabilities = ['message.send', 'message.read', 'message.ack']\n"
                    f"message_peers = {json.dumps(peers)}\n"
                )
            self.config.write_text(policy)
            self.config.chmod(0o600)
            request = await self.send(
                "user", "codex", "demo-work", "user-work", PROMPT, kind="work"
            )
            delivered = await self.receive("codex", "demo-work")
            self.save(
                {
                    "phase": "awaiting_initial_codex_edit",
                    "request": request,
                    "delivery": delivered,
                    "execution": "current Codex session",
                    "grok": "deterministic simulation; no provider configured",
                    "chatgpt_connector_verified": False,
                    "codex_cli_run_verified": False,
                }
            )
        else:
            data = json.loads(self.record.read_text())
            if stage == "stop":
                data["phase"] = "stopped"
                self.save(data)
                return data
            expected = {"review": "awaiting_initial_codex_edit", "finish": "awaiting_codex_rework"}[
                stage
            ]
            if data["phase"] != expected:
                raise RuntimeError(f"Stage blocked in phase {data['phase']}")
            page = self.root / "index.html"
            if stage == "review":
                data["initial_sha256"] = sha(page)
                (self.root / "initial.html").write_bytes(page.read_bytes())
                review = await self.send(
                    "codex",
                    "grok-sim",
                    "demo-review",
                    "review-1",
                    "SIMULATION: Prüfe den Webseitenauftrag. SHA256=" + data["initial_sha256"],
                    kind="work",
                )
                received = await self.receive("grok-sim", "demo-review")
                reply = await self.send(
                    "grok-sim",
                    "codex",
                    "demo-review",
                    "review-reply-1",
                    REVIEW,
                    kind="answer",
                    reply_to=received["id"],
                )
                delivery = await self.receive("codex", "demo-review")
                data.update(
                    review_request=review,
                    simulated_reply=reply,
                    rework_delivery=delivery,
                    phase="awaiting_codex_rework",
                )
            else:
                if sha(page) == data["initial_sha256"]:
                    raise RuntimeError("No Codex rework artifact change")
                checks = json.loads((self.root / "checks.json").read_text())
                if checks.get("page_sha256") != sha(page) or checks.get("passed") is not True:
                    raise RuntimeError("Passing checks for the final artifact required")
                result = await self.send(
                    "codex",
                    "user",
                    "demo-work",
                    "final-result",
                    json.dumps(
                        {
                            "page": "index.html",
                            "sha256": sha(page),
                            "review_reply_id": data["simulated_reply"]["id"],
                            "checks": checks,
                        },
                        ensure_ascii=False,
                    ),
                    kind="result",
                    reply_to=data["request"]["id"],
                )
                data.update(
                    result=result,
                    result_delivery=await self.receive("user", "demo-work"),
                    final_sha256=sha(page),
                    phase="completed",
                )
            self.save(data)
        return json.loads(self.record.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=["start", "review", "finish", "stop"])
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(Demo(args.root).run(args.stage)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
