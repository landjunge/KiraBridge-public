from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import uuid
from pathlib import Path

from pydantic import ValidationError

from kirabridge.audit_manager import verify
from kirabridge.bridge_core.bridge import Bridge
from kirabridge.bridge_core.config import load_config
from kirabridge.bridge_core.models import BridgeError, State, TaskRequest


def emit(value, *, stream=None):
    print(json.dumps(value, ensure_ascii=False, indent=2), file=stream or sys.stdout, flush=True)


def parse_request(path: str) -> TaskRequest:
    if path == "-":
        source = sys.stdin.read(2097153)
    else:
        with open(path, encoding="utf-8") as file:
            source = file.read(2097153)
    if len(source.encode()) > 2097152:
        raise BridgeError("payload_limit", "Request file exceeds 2 MiB")
    return TaskRequest.model_validate_json(source)


async def execute(args) -> None:
    if args.command == "setup":
        from kirabridge.local_runtime import setup

        emit(setup(args.workspace, Path(args.config) if args.config else None))
        return
    if args.command == "init":
        destination = Path(args.destination).expanduser().absolute()
        workspace = Path(args.workspace).expanduser().resolve(strict=True)
        if not workspace.is_dir():
            raise BridgeError("config_init", "Workspace must be a directory")
        # JSON strings are valid TOML basic strings for ordinary filesystem paths.
        content = (
            "data_dir = " + json.dumps(str(destination.parent / ".kirabridge-state")) + "\n"
            "[principals.local]\n"
            'capabilities = ["bridge.health", "task.read", "task.cancel", '
            '"file.list", "file.read", "clipboard.info"]\n'
            "roots = [" + json.dumps(str(workspace)) + "]\n"
            "executables = []\nagents = []\n"
        )
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(content)
        emit({"config": str(destination), "workspace": str(workspace)})
        return
    config = load_config(args.config)
    if args.command == "grok-connector":
        from kirabridge.grok_connector import effective_settings, state_dir
        from kirabridge.grok_connector.runtime import (
            connector_status,
            prepare,
            serve,
            start,
            stop,
        )
        from kirabridge.local_runtime import default_config

        config_path = Path(args.config).expanduser().absolute() if args.config else default_config()
        if args.action == "setup":
            emit(
                prepare(
                    config_path,
                    access=args.access,
                    cloudflared=args.cloudflared,
                    public_origin=args.public_origin,
                )
            )
        elif args.action == "start":
            emit(await start(config_path))
        elif args.action == "serve":
            try:
                await serve(config_path)
            except asyncio.CancelledError:
                pass
        elif args.action == "stop":
            emit(stop())
        elif args.action == "status":
            emit(connector_status(config))
        else:
            from kirabridge.grok_connector.auth_store import OAuthStore

            settings = effective_settings(config)
            if not settings.enabled:
                raise BridgeError("connector_disabled", "Start the local connector first")
            store = OAuthStore(
                state_dir(config) / "oauth.sqlite3",
                issuer=settings.public_origin,
                principal=settings.principal,
                redirect_hosts=settings.redirect_hosts,
            )
            try:
                if args.action == "approve":
                    store.decide(args.request_id, not args.deny)
                    emit({"id": args.request_id, "approved": not args.deny})
                else:
                    store.revoke_client(args.client_id)
                    emit({"revoked": True})
            finally:
                store.close()
        return
    if args.command == "team":
        from kirabridge.local_runtime import peer
        from kirabridge.mcp_gateway.client import MCPClientPool

        action = args.action
        tool = {
            "list": "team_list",
            "show": "team_get",
            "create": "team_create",
            "role": "team_set_role",
            "send": "team_message_send",
            "assign": "team_work_create",
            "work": "team_work_get" if getattr(args, "work_id", None) else "team_work_list",
            "inbox": "team_messages",
            "claim": "team_work_claim",
            "complete": "team_work_complete",
            "reprocess": "team_work_reprocess",
            "events": "team_events",
        }[action]
        arguments = {} if action == "list" else {"team_id": args.team_id}
        if action == "create":
            members = {name.strip(): "worker" for name in args.members.split(",") if name.strip()}
            arguments.update(
                name=args.name or args.team_id, members=members, coordinator=args.coordinator
            )
        elif action == "role":
            arguments.update(
                member=args.member,
                role=args.role,
                active=not args.disable,
                expected_revision=args.revision,
            )
        elif action == "send":
            arguments.update(
                recipient=args.recipient, body=args.text, kind=args.kind, reply_to=args.reply_to
            )
        elif action == "assign":
            arguments.update(
                assignee=args.assignee, title=args.title, body=args.text, parent_id=args.parent
            )
        elif action in {"claim", "complete", "reprocess"}:
            arguments["work_id"] = args.work_id
            if action == "complete":
                arguments.update(result=args.text, success=not args.failed)
            elif action == "reprocess":
                arguments.update(
                    core_task_id=args.core_task, expected_result_sha256=args.result_sha256
                )
        elif action == "work" and args.work_id:
            arguments["work_id"] = args.work_id
        writes = action in {"create", "role", "send", "assign", "claim", "complete", "reprocess"}
        if writes:
            arguments["idempotency_key"] = args.key or "cli-" + uuid.uuid4().hex
            arguments = {"request": arguments}
        async with MCPClientPool(call_timeout=20) as pool:
            await pool.connect(peer(config, args.principal))
            response = await pool.call("daemon", tool, arguments)
        result = response.structuredContent or {"error": {"code": "invalid_team_response"}}
        emit(result)
        if result.get("error"):
            raise SystemExit(2)
        return
    if args.command == "watch":
        from kirabridge.completion_client import CompletionClient
        from kirabridge.local_runtime import peer

        async with CompletionClient(peer(config, args.principal)) as client:
            await client.listen(
                args.target, lambda notice: emit(notice), once=args.once, timeout=args.timeout
            )
        return
    if args.command == "readiness":
        from kirabridge.local_runtime import connection_observer, peer
        from kirabridge.mcp_gateway.client import MCPClientPool
        from kirabridge.readiness import ReadinessInput, runtime_snapshot

        requirements = ReadinessInput(
            read_paths=args.read_path,
            executables=args.executable,
            operations=args.operation,
            workflow_id=args.workflow_id,
        )
        async with MCPClientPool(
            call_timeout=10, observer=connection_observer(config, args.principal)
        ) as pool:
            await pool.connect(peer(config, args.principal))
            response = await pool.call("daemon", "bridge_readiness", requirements.model_dump())
        result = response.structuredContent or {"error": {"code": "invalid_readiness"}}
        expected = runtime_snapshot(config)
        actual = result.get("runtime", {})
        matches = bool(actual) and all(
            actual.get(key) == expected[key]
            for key in [
                "config_path",
                "config_sha256",
                "effective_config_sha256",
                "source_tree_sha256",
            ]
        )
        result["service_matches_local_config_and_source"] = matches
        if not matches:
            from kirabridge.diagnostics import rejection_report, runtime_ref

            observer = connection_observer(config, args.principal)
            observer(
                "config.observed_drift",
                {
                    "previous_runtime": actual,
                    "outcome": "loaded_service_differs_from_local_snapshot",
                },
            )
            observer.close()
            result["requested_prerequisites_ready"] = False
            result["diagnostic"] = rejection_report(
                expected,
                "workflow.preflight",
                "loaded_service_drift",
                workflow_id=args.workflow_id,
            )
            result["diagnostic"]["loaded_service_runtime"] = runtime_ref(actual)
        emit(result)
        if (
            not matches
            or result.get("requested_prerequisites_ready") is False
            or result.get("error")
        ):
            raise SystemExit(1)
        return
    if args.command == "message":
        from kirabridge.local_runtime import connection_observer, peer
        from kirabridge.mcp_gateway.client import MCPClientPool
        from kirabridge.message_manager import MessageSend

        tool = {
            "send": "message_send",
            "receive": "message_receive",
            "ack": "message_ack",
            "get": "message_get",
            "release": "message_release",
            "conversation": "conversation_get",
            "status": "message_channel_status",
        }[args.action]
        payload = {}
        if args.action == "send":
            payload["message"] = MessageSend(
                recipient=args.recipient,
                conversation_id=args.conversation,
                idempotency_key=args.key,
                body=args.text,
                kind=args.kind,
                reply_to=args.reply_to,
                task_id=args.task_id,
                dispatch=not args.inbox_only,
                request_reply=False if args.no_reply else None,
            ).model_dump()
        elif args.action in {"get", "ack", "release"}:
            payload["message_id"] = args.message_id
            if args.action == "ack":
                payload["receipt"] = args.receipt
            if args.action == "release":
                payload["token"] = args.token
        elif args.action == "receive":
            payload = {"after": args.after, "limit": args.limit, "wait_seconds": args.wait}
        elif args.action == "conversation":
            payload["conversation_id"] = args.conversation
        async with MCPClientPool(
            call_timeout=30, observer=connection_observer(config, args.principal)
        ) as pool:
            await pool.connect(peer(config, args.principal))
            result = await pool.call("daemon", tool, payload)
            emit(result.structuredContent or {"error": {"code": "invalid_channel_response"}})
            if result.isError or (result.structuredContent or {}).get("error"):
                raise SystemExit(1)
        return
    if args.command in {"approvals", "approval-server"}:
        from kirabridge.console_runtime import open_console, serve_console
        from kirabridge.local_runtime import default_config

        config_path = Path(args.config).absolute() if args.config else default_config()
        if args.command == "approvals":
            emit(open_console(config_path))
        else:
            await serve_console(config, config_path)
        return
    if args.command == "chatgpt":
        from kirabridge.chatgpt_setup import wizard
        from kirabridge.local_runtime import default_config

        emit(
            wizard(
                config,
                Path(args.config).absolute() if args.config else default_config(),
                args.action,
            )
        )
        return
    if args.command in {"status", "service", "connect"}:
        from kirabridge.local_runtime import daemon_health, default_config, install_service

        if args.command == "connect":
            from kirabridge.mcp_gateway.proxy import connect_stdio

            await connect_stdio(config, args.principal)
        elif args.command == "service":
            if args.action == "install":
                emit(
                    install_service(
                        Path(args.config).absolute() if args.config else default_config()
                    )
                )
            else:
                emit(await daemon_health(config, args.principal))
        else:
            emit(await daemon_health(config, args.principal))
        return
    if args.command == "serve" and args.transport == "http":
        from kirabridge.local_runtime import load_service_credentials

        load_service_credentials(config)
        config.validate_network()
    bridge = Bridge(config)
    try:
        if args.command == "serve":
            from kirabridge.mcp_gateway.server import create_server

            async with bridge:
                if args.transport == "stdio":
                    await create_server(bridge, principal=args.principal).run_stdio_async()
                else:
                    import uvicorn

                    from kirabridge.mcp_gateway.http import create_http_app

                    server = uvicorn.Server(
                        uvicorn.Config(
                            create_http_app(bridge),
                            host=config.host,
                            port=config.port,
                            ssl_certfile=config.tls_cert,
                            ssl_keyfile=config.tls_key,
                            access_log=False,
                            log_level="critical",
                            limit_concurrency=config.max_http_requests,
                            timeout_keep_alive=5,
                        )
                    )
                    await server.serve()
            return
        if args.command == "grant":
            request = parse_request(args.request)
            bridge.validate(request)
            # Bind the reviewed request to a one-use token. Never expose this authority over MCP.
            token = bridge.security.grant(args.principal, request, args.ttl)
            print(token)
        elif args.command in {"run", "retry"}:
            request = parse_request(args.request)
            bridge.validate(request)
            await run_request(
                bridge,
                args.principal,
                request,
                args.wait,
                args.approve,
                args.original if args.command == "retry" else None,
            )
        elif args.command in {"ls", "read", "write", "exec", "ask", "clipboard"}:
            policy = config.principals.get(args.principal)
            if not policy or not policy.roots:
                raise BridgeError("workspace_missing", "Configure an allowed workspace first")
            root = policy.roots[0]
            if args.command in {"ls", "read", "write"}:
                path = str(Path(args.path or root).expanduser().absolute())
                operation = {"ls": "file.list", "read": "file.read", "write": "file.write"}[
                    args.command
                ]
                arguments = {"path": path}
                if args.command == "write":
                    arguments.update(text=args.text, overwrite=args.overwrite)
            elif args.command == "exec":
                argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
                operation, arguments = (
                    "terminal.execute",
                    {"argv": argv, "cwd": args.cwd or root, "timeout": args.timeout},
                )
            elif args.command == "ask":
                operation, arguments = (
                    "agent.execute",
                    {
                        "agent": args.agent,
                        "prompt": args.prompt,
                        "cwd": args.cwd or root,
                        "timeout": args.timeout,
                    },
                )
            else:
                operation = "clipboard." + args.action
                arguments = {"text": args.text} if args.action == "write" else {}
            identifier = "local-" + uuid.uuid4().hex
            request = TaskRequest(
                task_id=identifier,
                idempotency_key=identifier,
                operation=operation,
                arguments=arguments,
            )
            await run_request(bridge, args.principal, request, 3700, True)
        elif args.command == "pending":
            rows = bridge.store.db.execute(
                "SELECT id FROM tasks WHERE state='created' ORDER BY created LIMIT 100"
            )
            emit(
                {
                    "requests": [bridge.store.get(row[0]) for row in rows],
                    "approve_command": "kirabridge approve TASK_ID",
                }
            )
        elif args.command == "approve":
            approved = bridge.tasks.approve(args.task_id)
            emit(approved)
        elif args.command == "deny":
            task = bridge.store.get(args.task_id)
            if task["state"] not in {State.CREATED, State.QUEUED}:
                raise BridgeError("state_conflict", "Only pending or queued requests can be denied")
            bridge.store.transition(
                args.task_id,
                State.CANCELLED,
                {"source": "local_operator_rejection"},
                expected_states={State.CREATED, State.QUEUED},
            )
            emit(bridge.store.get(args.task_id))
        elif args.command == "enqueue":
            request = parse_request(args.request)
            emit(bridge.submit(args.principal, request, os.environ.get("KIRABRIDGE_APPROVAL", "")))
        elif args.command == "task":
            emit(bridge.task(args.principal, args.task_id))
        elif args.command == "tasks":
            emit(bridge.list_tasks(args.principal, args.after, args.limit, args.state))
        elif args.command == "audit":
            if args.export:
                from kirabridge.diagnostics import export_audit

                emit(export_audit(bridge.store, Path(args.export), args.after, args.limit))
            else:
                emit(verify(bridge.store))
        elif args.command == "diagnose":
            from kirabridge.diagnostics import task_report

            emit(task_report(bridge, args.principal, args.task_id))
        elif args.command == "reconcile":
            # A local operator attests an inspected external result. Does not execute or retry.
            emit(bridge.tasks.reconcile(args.task_id, State(args.state), args.evidence))
        elif args.command == "doctor":
            from kirabridge.platform_adapters import current_platform

            emit(
                {
                    "python": sys.version.split()[0],
                    "platform": current_platform().name,
                    "database": "ok",
                    "schema": 2,
                    "audit": verify(bridge.store),
                    "agents": bridge.agents.inventory(list(config.agents)),
                    "chatgpt_integration": "unverified",
                }
            )
    finally:
        # __aexit__ also closes; sqlite close is idempotent.
        bridge.store.close()


async def run_request(bridge, principal, request, wait, approve, original=None):
    bridge.validate(request)
    approval = (
        bridge.security.grant(principal, request)
        if approve
        else os.environ.get("KIRABRIDGE_APPROVAL", "")
    )
    if original:
        bridge.tasks.retry(principal, original, request, approval)
    else:
        bridge.submit(principal, request, approval)
    owns_dispatcher = False
    try:
        await bridge.tasks.start()
        owns_dispatcher = True
    except BridgeError as exc:
        if exc.code != "already_running":
            raise
    try:
        final = await bridge.tasks.wait(principal, request.task_id, wait)
        if final["state"] in {State.FAILED, State.UNKNOWN, State.BLOCKED}:
            final = bridge.task(principal, request.task_id)
        emit(final)
    finally:
        if owns_dispatcher:
            await bridge.tasks.stop()
    if final["state"] != State.COMPLETED:
        raise SystemExit(3 if final["state"] == State.UNKNOWN else 2)


def main() -> None:
    parser = argparse.ArgumentParser(description="KiraBridge private desktop bridge")
    parser.add_argument("--config", help="TOML policy file (or KIRABRIDGE_CONFIG)")
    parser.add_argument("--principal", default="local", help="Local CLI/stdio policy identity")
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("setup", help="Create private local policy, credentials and CLI command")
    setup.add_argument("--workspace", default=str(Path.home() / "workspace/KiraBridge"))
    sub.add_parser("status", help="Query the running local daemon")
    connector = sub.add_parser("grok-connector", help="Connect the Grok app/Eve through OAuth MCP")
    connector_actions = connector.add_subparsers(dest="action", required=True)
    preparation = connector_actions.add_parser("setup")
    preparation.add_argument("--access", choices=["team", "same-as-chatgpt"], default="team")
    preparation.add_argument("--cloudflared", help="Existing official cloudflared binary")
    preparation.add_argument(
        "--public-origin", help="Existing stable HTTPS origin; no quick tunnel"
    )
    for action in ("start", "serve", "status", "stop"):
        connector_actions.add_parser(action)
    approval = connector_actions.add_parser("approve")
    approval.add_argument("request_id")
    approval.add_argument("--deny", action="store_true")
    connector_actions.add_parser("revoke").add_argument("client_id")
    team = sub.add_parser("team", help="Shared roles, addressed messages and delegated work")
    actions = team.add_subparsers(dest="action", required=True)
    actions.add_parser("list")
    for action in ("show", "inbox", "events"):
        actions.add_parser(action).add_argument("team_id")
    work = actions.add_parser("work")
    work.add_argument("team_id")
    work.add_argument("--work-id")
    create = actions.add_parser("create")
    create.add_argument("team_id")
    create.add_argument("--name")
    create.add_argument(
        "--members", required=True, help="Comma-separated operator-enabled identities"
    )
    create.add_argument("--coordinator", required=True)
    role = actions.add_parser("role")
    role.add_argument("team_id")
    role.add_argument("member")
    role.add_argument("role", choices=["coordinator", "worker", "reviewer", "observer"])
    role.add_argument("--revision", type=int, required=True)
    role.add_argument("--disable", action="store_true")
    send = actions.add_parser("send")
    send.add_argument("team_id")
    send.add_argument("recipient")
    send.add_argument("text")
    send.add_argument(
        "--kind", choices=["question", "answer", "work", "result", "note"], default="question"
    )
    send.add_argument("--reply-to")
    assign = actions.add_parser("assign")
    assign.add_argument("team_id")
    assign.add_argument("assignee")
    assign.add_argument("text")
    assign.add_argument("--title", default="Teamauftrag")
    assign.add_argument("--parent")
    for action in ("claim", "complete"):
        command = actions.add_parser(action)
        command.add_argument("team_id")
        command.add_argument("work_id")
        if action == "complete":
            command.add_argument("text")
            command.add_argument("--failed", action="store_true")
    reprocess = actions.add_parser("reprocess")
    reprocess.add_argument("team_id")
    reprocess.add_argument("work_id")
    reprocess.add_argument("--core-task", required=True)
    reprocess.add_argument("--result-sha256", required=True)
    for command in (
        reprocess,
        create,
        role,
        send,
        assign,
        actions.choices["claim"],
        actions.choices["complete"],
    ):
        command.add_argument(
            "--key", help="Reuse this key for exactly the same operation; never blindly repeat work"
        )
    readiness = sub.add_parser(
        "readiness", help="Check requested prerequisites on the loaded daemon"
    )
    readiness.add_argument("--read-path", action="append", default=[])
    readiness.add_argument("--executable", action="append", default=[])
    readiness.add_argument("--operation", action="append", default=[])
    readiness.add_argument("--workflow-id")
    sub.add_parser("connect", help="Forward MCP stdio to the authenticated local daemon")
    message = sub.add_parser("message", help="Authenticated addressed agent messaging")
    message_actions = message.add_subparsers(dest="action", required=True)
    send = message_actions.add_parser("send")
    send.add_argument("recipient")
    send.add_argument("text")
    send.add_argument("--conversation", required=True)
    send.add_argument("--key", required=True, help="Stable idempotency key for this exact message")
    send.add_argument(
        "--kind", choices=["question", "answer", "work", "result", "note"], default="question"
    )
    send.add_argument("--reply-to")
    send.add_argument("--task-id")
    send.add_argument("--inbox-only", action="store_true", help="Do not invoke a managed agent")
    send.add_argument("--no-reply", action="store_true")
    receive = message_actions.add_parser("receive")
    receive.add_argument("--after", type=int, default=0)
    receive.add_argument("--limit", type=int, default=20)
    receive.add_argument("--wait", type=float, default=0)
    get = message_actions.add_parser("get")
    get.add_argument("message_id")
    release = message_actions.add_parser("release")
    release.add_argument("message_id")
    release.add_argument("--token", required=True, choices=["go-go-go"])
    ack = message_actions.add_parser("ack")
    ack.add_argument("message_id")
    ack.add_argument("--receipt", required=True)
    conversation = message_actions.add_parser("conversation")
    conversation.add_argument("conversation")
    message_actions.add_parser("status")
    sub.add_parser("approvals", help="Open the private local approval page in your browser")
    sub.add_parser("approval-server", help="Run the loopback-only local approval interface")
    chatgpt = sub.add_parser("chatgpt", help="Local account linking for a private ChatGPT tunnel")
    chatgpt.add_argument("action", choices=["setup", "status"])
    service = sub.add_parser("service")
    service.add_argument("action", choices=["install", "status"])
    sub.add_parser("pending", help="Review requests awaiting local approval")
    approve = sub.add_parser("approve", help="Approve exactly one previously reviewed pending task")
    approve.add_argument("task_id")
    deny = sub.add_parser("deny", help="Reject one pending or queued request without executing it")
    deny.add_argument("task_id")
    for name in ("ls", "read", "write"):
        command = sub.add_parser(name)
        command.add_argument("path", nargs="?" if name == "ls" else None)
        if name == "write":
            command.add_argument("text")
            command.add_argument("--overwrite", action="store_true")
    command = sub.add_parser("exec", help="Locally approve and execute an exact argv list")
    command.add_argument("--cwd")
    command.add_argument("--timeout", type=float, default=60)
    command.add_argument("argv", nargs=argparse.REMAINDER)
    command = sub.add_parser("ask", help="Run a configured agent turn")
    command.add_argument("agent")
    command.add_argument("prompt")
    command.add_argument("--cwd")
    command.add_argument("--timeout", type=float, default=120)
    command = sub.add_parser("clipboard")
    command.add_argument("action", choices=["info", "read", "write"])
    command.add_argument("text", nargs="?")
    serve = sub.add_parser("serve")
    serve.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    init = sub.add_parser("init")
    init.add_argument(
        "destination", help="New private TOML file; existing files are never replaced"
    )
    init.add_argument("--workspace", required=True, help="Existing allowed workspace directory")
    for name in ("grant", "run", "enqueue", "retry"):
        command = sub.add_parser(name)
        command.add_argument("request", help="Exact version-1 request JSON file, or - for stdin")
        if name == "grant":
            command.add_argument("--ttl", type=int, default=300)
        elif name in {"run", "retry"}:
            if name == "retry":
                command.add_argument(
                    "--original", required=True, help="Proven not-started failed task"
                )
            command.add_argument(
                "--approve", action="store_true", help="Explicitly approve this exact request"
            )
            command.add_argument("--wait", type=float, default=3700)
    watch = sub.add_parser("watch", help="Receive/print own completions automatically, then ack")
    watch.add_argument("--target", default="default", help="Stable requesting assistant/session ID")
    watch.add_argument("--once", action="store_true")
    watch.add_argument("--timeout", type=float, help="Optional total listener deadline in seconds")
    task = sub.add_parser("task")
    task.add_argument("task_id")
    tasks = sub.add_parser("tasks")
    tasks.add_argument("--after", type=int, default=0)
    tasks.add_argument("--limit", type=int, default=100)
    tasks.add_argument("--state", choices=[state.value for state in State])
    audit = sub.add_parser("audit")
    audit.add_argument("--export", help="New private bounded segment of the existing audit chain")
    audit.add_argument("--after", type=int, default=0)
    audit.add_argument("--limit", type=int, default=500)
    diagnose = sub.add_parser("diagnose", help="Compact own task diagnostic without raw arguments")
    diagnose.add_argument("task_id")
    sub.add_parser("doctor")
    reconcile = sub.add_parser("reconcile")
    reconcile.add_argument("task_id")
    reconcile.add_argument("--state", choices=["completed", "failed", "cancelled"], required=True)
    reconcile.add_argument(
        "--evidence", required=True, help="Reviewed result reference; no credentials"
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.CRITICAL, stream=sys.stderr)
    try:
        asyncio.run(execute(args))
    except (BridgeError, ValidationError, OSError, ValueError, TimeoutError) as exc:
        code = exc.code if isinstance(exc, BridgeError) else "invalid_request"
        output = {"error": {"code": code}}
        if hasattr(exc, "diagnostic"):
            output["diagnostic"] = exc.diagnostic
        emit(
            output,
            stream=sys.stderr if args.command in {"serve", "connect"} else sys.stdout,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
