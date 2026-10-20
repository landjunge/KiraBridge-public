"""Durable handoffs to exact existing visible terminals; never spawn a fallback."""

import asyncio
import re
import time

from kirabridge.bridge_core.models import BridgeError, UncertainExecution, canonical, digest
from kirabridge.message_manager import MessageSend
from kirabridge.session_manager import SessionInput
from kirabridge.visible_readiness import assess, input_view
from kirabridge.voice_channel import IDENTITIES


class VisibleReadinessError(BridgeError):
    def __init__(self, observation):
        self.observation = observation
        code = {
            "working": "visible_target_working",
            "input_not_empty": "visible_input_not_empty",
            "scrolled": "visible_target_scrolled",
            "unknown": "visible_target_unknown",
            "target_changed": "visible_target_changed",
        }[observation["state"]]
        message = {
            "working": "Der Agent arbeitet noch; die Nachricht wartet ohne Eingabe.",
            "input_not_empty": "Im Eingabefeld steht bereits Text; er wird nicht überschrieben.",
            "scrolled": "Die aktuelle Eingabeansicht ist nicht erreichbar; Nachricht wartet.",
            "unknown": "Die aktuelle Eingabebereitschaft ist nicht eindeutig; keine Eingabe.",
            "target_changed": "Die zugeordnete CLI-Sitzung hat sich geändert; keine Eingabe.",
        }[observation["state"]]
        super().__init__(code, message)


class VisibleHandoffs:
    def activation_work_count(self, *, active_only=False, context=None):
        db = context.db if context is not None else self.store.db
        return db.execute(
            "SELECT count(*) FROM visible_handoffs WHERE state IN "
            "('planned','inserting','inserted','submitting','return_sent','sent','confirmed')"
        ).fetchone()[0]

    @staticmethod
    def input_view(target, text):
        """The last current input widget, never an older prompt in scrollback."""
        return input_view(target, text)

    @staticmethod
    def prompt(principal, target, identifier, body, message_id=None, conversation_id=None):
        message_id = message_id or "visible-" + digest(identifier)[:48]
        conversation_id = conversation_id or message_id
        name = IDENTITIES.get(principal, {}).get("name", principal)
        return (
            f"[KiraBridge Auftrag {identifier}] Von {name} ({principal}) an {target}. "
            "Bestehende sichtbare Sitzung, keine neue Hintergrundsitzung starten. "
            f"Zuerst über KiraBridge message_receive die Konversation {conversation_id} lesen und "
            f"Nachricht {message_id} mit deren receipt per message_ack bestätigen. "
            "Danach den folgenden Auftrag bearbeiten. Antworte am Ende sichtbar hier UND mit "
            f"message_send an {principal}, conversation_id={conversation_id}, "
            f"reply_to={message_id}, "
            "kind=result, request_reply=false, dispatch=false, eigener stabiler idempotency_key. "
            f"Die Auftrags-ID immer angeben. Auftrag:\n{body}\nKB-END-{digest(identifier)[:12]}"
        )

    @staticmethod
    def insertion_observed(target, text, prompt, identifier):
        raw_text = text
        text = VisibleHandoffs.input_view(target, text)
        if target == "grok":
            collapsed = re.search(r"\[Pasted: (\d+) lines\]", text)
            preceding = raw_text[: raw_text.rfind("╭")]
            preview = preceding[preceding.rfind("╭") :]
            if (
                collapsed
                and int(collapsed[1]) == prompt.count("\n") + 1
                and "KB-END-" + digest(identifier)[:12] in preview
                and "paste again or double-cli" in preview
            ):
                return "grok_collapsed_paste_lines_and_unique_preview_marker"
        if "KB-END-" + digest(identifier)[:12] in text:
            return "visible_end_marker"
        # Real Codex collapses multiline pastes; the empty pre-state and exact
        # length bind this observable representation to the just-authorized paste.
        if target == "codex":
            match = re.search(r"(?m)^\s*› \[Pasted Content (\d+) chars\]\s*$", text)
            if match and int(match[1]) == len(prompt):
                return "codex_collapsed_paste_exact_character_count"
        return None

    def __init__(self, config, store, security, sessions, messages):
        self.config, self.store, self.security = config, store, security
        self.sessions, self.messages = sessions, messages
        from kirabridge.platform_adapters.codex_state import CodexTurnState

        self.codex_state = CodexTurnState()
        with store.transaction():
            store.db.execute(
                "CREATE TABLE IF NOT EXISTS visible_handoffs ("
                "id TEXT PRIMARY KEY,principal TEXT NOT NULL,target TEXT NOT NULL,"
                "request_hash TEXT NOT NULL,binding TEXT NOT NULL,message_id TEXT NOT NULL,"
                "state TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,"
                "evidence TEXT NOT NULL)"
            )
            store.db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS visible_target_active "
                "ON visible_handoffs(target) "
                "WHERE state IN ('planned','inserting','inserted','submitting',"
                "'return_sent','sent','confirmed')"
            )
            store.db.execute(
                "CREATE TABLE IF NOT EXISTS visible_handoff_events ("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "id TEXT NOT NULL REFERENCES visible_handoffs(id),"
                "at REAL NOT NULL,state TEXT NOT NULL,evidence TEXT NOT NULL)"
            )

    def status(self, principal, identifier):
        self.security.principal(principal, "task.read")
        row = self.store.db.execute(
            "SELECT * FROM visible_handoffs WHERE id=? AND (principal=? OR target=?)",
            (identifier, principal, principal),
        ).fetchone()
        if not row:
            raise BridgeError("not_found", "Visible handoff not found")
        import json

        result = dict(row)
        result["binding"] = json.loads(result["binding"])
        result["evidence"] = json.loads(result["evidence"])
        result["events"] = [
            {**dict(e), "evidence": json.loads(e["evidence"])}
            for e in self.store.db.execute(
                "SELECT seq,at,state,evidence FROM visible_handoff_events WHERE id=? ORDER BY seq",
                (identifier,),
            )
        ]
        return result

    def reconcile(self, principal, identifier):
        """Read authenticated evidence after an uncertain outcome; never send input."""
        status = self.status(principal, identifier)
        message = self.messages.get(principal, status["message_id"])
        if message["acknowledged"] and status["state"] not in {"completed", "interrupted"}:
            evidence = {
                "authenticated_principal": status["target"],
                "message_id": status["message_id"],
                "agent_confirmed": True,
                "reconciled_without_input": True,
            }
            if status["state"] != "confirmed":
                self.transition(identifier, "confirmed", evidence)
            reply = self.store.db.execute(
                "SELECT id FROM messages WHERE reply_to=? AND sender=? AND recipient=? "
                "AND kind IN ('answer','result') ORDER BY seq LIMIT 1",
                (status["message_id"], status["target"], status["principal"]),
            ).fetchone()
            if reply:
                self.transition(identifier, "completed", {**evidence, "reply_id": reply["id"]})
        return self.status(principal, identifier)

    def transition(self, identifier, state, evidence):
        with self.store.transaction():
            current = self.store.db.execute(
                "SELECT state FROM visible_handoffs WHERE id=?", (identifier,)
            ).fetchone()
            if current and current[0] in {"completed", "interrupted"}:
                return  # Completed evidence is terminal, including after a late callback failure.
            now = time.time()
            self.store.db.execute(
                "UPDATE visible_handoffs SET state=?,updated=?,evidence=? WHERE id=?",
                (state, now, canonical(evidence), identifier),
            )
            self.store.db.execute(
                "INSERT INTO visible_handoff_events(id,at,state,evidence) VALUES(?,?,?,?)",
                (identifier, now, state, canonical(evidence)),
            )
            row = self.store.db.execute(
                "SELECT principal FROM visible_handoffs WHERE id=?", (identifier,)
            ).fetchone()
            self.store.audit(
                "control.handoff." + state, row[0], None, {"handoff_id": identifier, **evidence}
            )

    async def observe_readiness(self, principal, output):
        for target, binding in self.config.visible_handoffs.bindings.items():
            if (output.get("pane_id"), output.get("expected_pid")) != (
                binding.pane_id,
                binding.expected_pid,
            ):
                continue
            selected = await self.sessions.selected(
                principal, binding.pane_id, binding.expected_pid
            )
            if not any(
                p["pid"] == binding.agent_pid and p["name"] == target
                for p in selected.get("processes", [])
            ):
                return {
                    "state": "target_changed",
                    "ready": False,
                    "reason": "bound_agent_pid_not_present",
                    "target": target,
                    "observed_at": time.time(),
                }
            protocol = None
            if target == "codex" and binding.codex_thread_id:
                protocol = await self.codex_state.read(
                    binding.codex_rollout_path, binding.codex_thread_id
                )
            return {
                **assess(target, output["text"], binding, protocol),
                "binding": {
                    "pane_id": binding.pane_id,
                    "expected_pid": binding.expected_pid,
                    "agent_pid": binding.agent_pid,
                },
                "protocol": protocol,
                "observed_at": time.time(),
                "scope": "current input and separately bound turn observation; no input proof",
            }
        return None

    async def dispatch_ready(self, principal, target):
        """Observe before claiming a message; never paste or settle unknown input."""
        binding = self.config.visible_handoffs.bindings.get(target)
        if binding is None:
            raise BridgeError("visible_target_missing", "No assigned existing visible terminal")
        # An old uncertain input remains owned until actual receipt is reconciled.
        active = self.store.db.execute(
            "SELECT id,principal FROM visible_handoffs WHERE target=? AND state IN "
            "('planned','inserting','inserted','submitting','return_sent','sent','confirmed','unknown')",
            (target,),
        ).fetchone()
        if active:
            self.reconcile(active["principal"], active["id"])
            state = self.store.db.execute(
                "SELECT state FROM visible_handoffs WHERE id=?", (active["id"],)
            ).fetchone()[0]
            if state not in {"completed", "interrupted"}:
                error = BridgeError(
                    "visible_target_busy", "Existing handoff must finish or reconcile"
                )
                error.observation = {
                    "state": "reserved",
                    "handoff_id": active["id"],
                    "handoff_state": state,
                    "next_step": "Empfang und Antwort dieses Auftrags abgleichen; nicht neu senden",
                }
                status = self.status(active["principal"], active["id"])
                message = self.messages.get(active["principal"], status["message_id"])
                last = status["events"][-1] if status["events"] else None
                error.observation.update(
                    message_id=message["id"],
                    acknowledged=message["acknowledged"],
                    last_event={key: last[key] for key in ("state", "at")} if last else None,
                )
                raise error
        await self.check_target(principal, target, binding, ready=True)

    async def check_target(self, principal, target, binding, *, ready=False):
        row = await self.sessions.selected(principal, binding.pane_id, binding.expected_pid)
        matches = [
            p
            for p in row.get("processes", [])
            if p["pid"] == binding.agent_pid and p["name"] == target
        ]
        if len(matches) != 1:
            raise BridgeError(
                "visible_target_changed", "Bound CLI process is not in this exact terminal"
            )
        output = await self.sessions.read(principal, binding.pane_id, binding.expected_pid)
        if ready:
            observation = await self.observe_readiness(
                principal,
                {**output, "pane_id": binding.pane_id, "expected_pid": binding.expected_pid},
            )
            if not observation["ready"]:
                # Store raw contents only in the bounded capture repository.
                observed = self.sessions.audit.observe_terminal(
                    principal,
                    {**output, "pane_id": binding.pane_id, "expected_pid": binding.expected_pid},
                )
                raise VisibleReadinessError(
                    {
                        **observation,
                        "observed_at": time.time(),
                        "output_ref": observed.get("output_ref"),
                    }
                )
        return output

    async def submit_inserted(self, identifier, principal, target, binding, running):
        """Exactly one separately recorded Return; never call after an uncertain submit."""
        self.transition(identifier, "submitting", {"agent_confirmed": False})
        await self.check_target(principal, target, binding)
        await self.sessions.press_return(principal, binding.pane_id, binding.expected_pid)
        self.transition(identifier, "return_sent", {"return_sent": True, "agent_confirmed": False})
        # Return transport is separate from observable CLI acceptance.
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            view = await self.check_target(principal, target, binding)
            if re.search(binding.ready_pattern, self.input_view(target, view["text"])):
                break
            await asyncio.sleep(0.1)
        else:
            raise UncertainExecution(
                "visible_submit_unknown",
                "Input field did not clear after Return; do not repeat",
            )
        self.transition(
            identifier,
            "sent",
            {"return_sent": True, "input_field_cleared": True, "agent_confirmed": False},
        )
        await running({"handoff_id": identifier, "state": "sent", "agent_confirmed": False})

    async def continue_unsubmitted(self, principal, identifier, running):
        """Explicit local reconciliation, no new paste and no repeat of a prior Return."""
        from kirabridge.bridge_core.config import VisibleTerminalBinding

        status = self.status(principal, identifier)
        message = self.messages.get(principal, status["message_id"])
        if message["acknowledged"]:
            return self.reconcile(principal, identifier)
        attempted_return = any(
            e["state"] in {"submitting", "return_sent", "sent", "confirmed"}
            for e in status["events"]
        )
        if (
            status["state"] != "unknown"
            or status["evidence"].get("reason") != "visible_insert_unknown"
            or attempted_return
        ):
            raise BridgeError(
                "return_reconciliation_required", "A Return may already have been sent"
            )
        binding = VisibleTerminalBinding.model_validate(status["binding"])
        if self.config.visible_handoffs.bindings.get(status["target"]) != binding:
            raise BridgeError("handoff_conflict", "Original binding changed")
        view = await self.check_target(principal, status["target"], binding)
        prompt = self.prompt(
            principal,
            status["target"],
            identifier,
            message["body"],
            message["id"],
            message["conversation_id"],
        )
        observed = self.insertion_observed(status["target"], view["text"], prompt, identifier)
        if not observed:
            raise BridgeError("visible_insert_unknown", "Original unsubmitted paste is not visible")
        self.transition(
            identifier,
            "inserted",
            {
                "insertion_representation": observed,
                "reconciled_without_paste": True,
                "return_sent": False,
                "agent_confirmed": False,
            },
        )
        try:
            await self.submit_inserted(identifier, principal, status["target"], binding, running)
        except BaseException as exc:
            self.transition(
                identifier,
                "unknown",
                {"reason": getattr(exc, "code", "interrupted"), "automatic_retry": False},
            )
            raise
        return self.status(principal, identifier)

    async def execute(self, task, args, running, progress):
        principal, target, identifier = task["principal"], args.agent, task["id"]
        # All senders use this path. Eve is grok_app; only target selects the CLI window.
        for capability in ("agent.execute", "session.inspect", "session.input", "terminal.execute"):
            self.security.principal(principal, capability)
        binding = self.config.visible_handoffs.bindings.get(target)
        if binding is None:
            raise BridgeError(
                "visible_target_missing",
                "Bind an exact existing visible CLI terminal; no background fallback",
            )
        reply_binding = None
        if principal in {"codex", "grok"}:
            reply_binding = self.config.visible_handoffs.bindings.get(principal)
            if reply_binding is None:
                raise BridgeError(
                    "visible_reply_target_missing",
                    "The requesting CLI needs its assigned visible window",
                )
            await self.check_target(principal, principal, reply_binding)
        hashed = digest({"principal": principal, "args": args.model_dump()})
        existing = self.store.db.execute(
            "SELECT * FROM visible_handoffs WHERE id=?", (identifier,)
        ).fetchone()
        if existing:
            if existing["request_hash"] != hashed or existing["binding"] != canonical(
                binding.model_dump()
            ):
                raise BridgeError(
                    "handoff_conflict", "Original visible handoff and target are immutable"
                )
            reconciled = self.reconcile(principal, identifier)
            existing = {**dict(existing), "state": reconciled["state"]}
            if existing["state"] not in {"sent", "confirmed", "completed"}:
                raise UncertainExecution(
                    "visible_handoff_unknown",
                    "Prior input must be reconciled; never repeat automatically",
                )
            message_id = existing["message_id"]
        else:
            before = await self.check_target(principal, target, binding, ready=True)
            if "KB-END-" + digest(identifier)[:12] in before["text"]:
                raise BridgeError(
                    "visible_marker_collision", "This handoff marker was already visible"
                )
            addressed = task.get("visible_message_id")
            if addressed:
                original = self.messages.get(principal, addressed)
                if original["sender"] != principal or original["recipient"] != target:
                    raise BridgeError(
                        "handoff_conflict", "Original addressed message does not match"
                    )
                message_id, conversation = addressed, original["conversation_id"]
            else:
                message_id = conversation = "visible-" + digest(identifier)[:48]
            prompt = self.prompt(
                principal, target, identifier, args.prompt, message_id, conversation
            )
            if len(prompt) > 16384 or "\x00" in prompt:
                raise BridgeError("payload_limit", "Visible prompt exceeds terminal input limit")
            with self.store.transaction():
                self.store.assert_accepting(continuation_id=identifier, owned_execution=True)
                active = self.store.db.execute(
                    "SELECT id FROM visible_handoffs WHERE target=? AND state IN "
                    "('planned','inserting','inserted','submitting','return_sent',"
                    "'sent','confirmed','unknown')",
                    (target,),
                ).fetchone()
                if active:
                    raise BridgeError(
                        "visible_target_busy",
                        "Another handoff owns this terminal; reconcile it first",
                    )
                if not addressed:
                    self.messages._send(
                        principal,
                        MessageSend(
                            message_id=message_id,
                            recipient=target,
                            conversation_id=conversation,
                            idempotency_key=message_id,
                            kind="work",
                            body=args.prompt,
                            request_reply=True,
                            dispatch=False,
                        ),
                        visible_internal=True,
                    )
                now = time.time()
                self.store.db.execute(
                    "INSERT INTO visible_handoffs VALUES(?,?,?,?,?,?,'planned',?,?,?)",
                    (
                        identifier,
                        principal,
                        target,
                        hashed,
                        canonical(binding.model_dump()),
                        message_id,
                        now,
                        now,
                        canonical({"agent_confirmed": False}),
                    ),
                )
            input_attempted = False
            try:
                await self.check_target(principal, target, binding, ready=True)
                self.transition(
                    identifier,
                    "inserting",
                    {
                        "agent_confirmed": False,
                        "marker_preexisting": False,
                        "empty_input_observed": True,
                        "terminal_input_attempted": True,
                    },
                )
                input_attempted = True
                await self.sessions.insert(
                    principal,
                    SessionInput(
                        pane_id=binding.pane_id,
                        expected_pid=binding.expected_pid,
                        text=prompt,
                        submit=False,
                    ),
                )
                inserted = await self.check_target(principal, target, binding)
                observed = self.insertion_observed(target, inserted["text"], prompt, identifier)
                if not observed:
                    raise UncertainExecution(
                        "visible_insert_unknown", "Prompt insertion not observed; no Return sent"
                    )
                self.transition(
                    identifier,
                    "inserted",
                    {
                        "prompt_observed": True,
                        "insertion_representation": observed,
                        "return_sent": False,
                        "agent_confirmed": False,
                    },
                )
                await progress(
                    {"handoff_id": identifier, "state": "inserted", "agent_confirmed": False}
                )
                await self.submit_inserted(identifier, principal, target, binding, running)
            except BaseException as exc:
                if not input_attempted:
                    self.transition(
                        identifier,
                        "interrupted",
                        {
                            "reason": getattr(exc, "code", "preinput_error"),
                            "preinput_abort": True,
                            "terminal_input_attempted": False,
                            "automatic_retry": False,
                        },
                    )
                    raise  # Only a pre-input readiness error may be deferred by the receiver.
                self.transition(
                    identifier,
                    "unknown",
                    {
                        "reason": getattr(exc, "code", "interrupted"),
                        "agent_confirmed": False,
                        "automatic_retry": False,
                    },
                )
                raise UncertainExecution(
                    "visible_handoff_unknown",
                    "Input outcome requires reconciliation; no automatic resend",
                ) from exc
        try:
            async with asyncio.timeout(args.timeout):
                confirmed = False
                while True:
                    message = self.messages.get(principal, message_id)
                    current = self.reconcile(principal, identifier)
                    if current["state"] == "interrupted":
                        raise UncertainExecution(
                            "agent_turn_interrupted", "Interrupted turn must not be repeated"
                        )
                    if (
                        message["acknowledged"]
                        and not confirmed
                        and current["state"] != "completed"
                    ):
                        confirmed = True
                        self.transition(
                            identifier,
                            "confirmed",
                            {
                                "authenticated_principal": target,
                                "message_id": message_id,
                                "agent_confirmed": True,
                            },
                        )
                        await progress(
                            {
                                "handoff_id": identifier,
                                "state": "confirmed",
                                "agent_confirmed": True,
                            }
                        )
                    reply = self.store.db.execute(
                        "SELECT id,body FROM messages WHERE reply_to=? "
                        "AND sender=? AND recipient=? "
                        "AND kind IN ('answer','result') ORDER BY seq LIMIT 1",
                        (message_id, target, principal),
                    ).fetchone()
                    if message["acknowledged"] and reply:
                        # An answer returns through the active requesting MCP call;
                        # revalidate its assigned original window as well as the worker's.
                        await self.check_target(principal, target, binding)
                        if reply_binding:
                            await self.check_target(principal, principal, reply_binding)
                        evidence = {
                            "handoff_id": identifier,
                            "route": "existing_visible_terminal",
                            "agent_confirmed": True,
                            "reply_id": reply["id"],
                            "binding": binding.model_dump(),
                            "identity_scope": "authenticated_bridge_principal",
                            "reply_route": "active_request_result_and_durable_inbox",
                            "reply_target_binding": reply_binding.model_dump()
                            if reply_binding
                            else None,
                            "reply_visible_rendering": "client_not_attested",
                        }
                        self.transition(identifier, "completed", evidence)
                        return {
                            "success": True,
                            "text": reply["body"],
                            "evidence": evidence,
                            "scope": "agent_turn",
                            "project_completion_verified": False,
                        }
                    await asyncio.sleep(0.25)
        except BaseException as exc:
            self.transition(
                identifier, "unknown", {"reason": "reply_unconfirmed", "automatic_retry": False}
            )
            raise UncertainExecution(
                "visible_reply_unknown", "No confirmed final reply; do not resubmit"
            ) from exc
