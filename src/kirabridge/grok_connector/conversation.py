"""Return completed work inside Grok's tool turn, without replaying that work."""

from __future__ import annotations

import asyncio

from kirabridge import LOCAL_APPROVAL_URL
from kirabridge.bridge_core.models import BridgeError, State
from kirabridge.platform_adapters.desktop import DESKTOP_MESSAGES

WAIT_SECONDS = 18.0  # Below the existing gateway/client transport deadlines.
ACTIVE = {State.QUEUED, State.ACCEPTED, State.RUNNING}
MESSAGE_FAILURES = {State.FAILED, State.UNKNOWN, State.BLOCKED, State.CANCELLED}


def enabled_for(bridge, principal):
    settings = bridge.config.grok_connector
    return settings.enabled and principal == settings.principal


def confirmed_input_reply(bridge, principal, task, result):
    """A transport boolean is insufficient: require the central completed receipt."""
    evidence = result.get("evidence") or {}
    if (
        task["operation"] != "session.input"
        or evidence.get("route") != "existing_visible_terminal"
        or evidence.get("agent_confirmed") is not True
        or evidence.get("handoff_id") != task["id"]
        or not isinstance(result.get("text"), str)
        or not result["text"].strip()
        or not evidence.get("reply_id")
    ):
        return False
    try:
        status = bridge.visible_handoffs.status(principal, task["id"])
    except BridgeError:
        return False
    return (
        status["state"] == "completed"
        and status["binding"]["pane_id"] == task["args"]["pane_id"]
        and status["binding"]["expected_pid"] == task["args"]["expected_pid"]
        and status["evidence"].get("agent_confirmed") is True
        and status["evidence"].get("reply_id") == evidence["reply_id"]
        and (
            status["evidence"].get("identity_scope") == "authenticated_bridge_principal"
            or status["evidence"].get("authenticated_principal") == status["target"]
        )
    )


async def result_for_conversation(bridge, principal, task):
    """An authenticated tool response is not evidence of audio playback."""
    if not enabled_for(bridge, principal) or "id" not in task:
        return task
    # Re-read through the normal owner/permission check, including on reconnect.
    task = bridge.task(principal, task["id"])
    if task["state"] in ACTIVE:
        try:
            await bridge.tasks.wait(principal, task["id"], timeout=WAIT_SECONDS)
        except TimeoutError:
            pass
        task = bridge.task(principal, task["id"])

    state, operation = task["state"], task["operation"]
    result = task.get("result") or {}
    waiting = state in ACTIVE
    agent_reply = state == State.COMPLETED and confirmed_input_reply(
        bridge, principal, task, result
    )
    input_only = operation == "session.input" and state == State.COMPLETED and not agent_reply
    buffer = task.get("input_buffer") or {}
    if buffer.get("state") == "expired":
        text = "Die Terminal-Nachricht ist im Puffer verfallen und wurde nicht zugestellt."
    elif state == State.CREATED and buffer.get("state") == "waiting":
        text = (
            "Die Terminal-Nachricht liegt im Puffer und wartet auf Daniels separate Freigabe. "
            "Ohne Freigabe verfällt sie zum angegebenen expires-Zeitpunkt."
        )
    elif state == State.CREATED:
        text = "Der Auftrag wartet auf deine Erlaubnis in KiraBridge."
    elif waiting:
        text = "Der Auftrag läuft noch. Eine fertige Antwort liegt noch nicht vor."
    elif input_only:
        text = (
            "Die Eingabe ist im gewählten Terminal zugestellt. "
            "Eine Antwort ist noch nicht bestätigt."
        )
    elif state == State.COMPLETED:
        text = result.get("final_message") or result.get("text") or result.get("stdout") or ""
        if not isinstance(text, str):
            text = ""
        if not text and result.get("output_available") is False:
            text = (
                "Der Auftrag ist abgeschlossen. Die gespeicherte Terminalausgabe ist "
                "nicht mehr verfügbar. Der Auftrag wird nicht erneut ausgeführt."
            )
        elif not text:
            text = (
                "Der Auftrag ist abgeschlossen. "
                "Die tatsächlichen Ergebnisse stehen im Ergebnisfeld."
            )
    else:
        error = task.get("error") or {}
        text = {
            State.UNKNOWN: "Der Ausgang ist unklar. Der Auftrag wird nicht erneut gestartet.",
            State.CANCELLED: "Der Auftrag wurde abgebrochen.",
            State.BLOCKED: "Der Auftrag ist blockiert.",
        }.get(state, "Der Auftrag ist fehlgeschlagen.")
        detail = (
            result.get("final_message")
            or result.get("text")
            or result.get("stderr")
            or error.get("message")
            or DESKTOP_MESSAGES.get(error.get("code"))
        )
        if isinstance(detail, str) and detail:
            text += " " + detail

    response = {
        **task,
        "approval_required": state == State.CREATED,
        "local_approval_url": LOCAL_APPROVAL_URL,
        "conversation_return": {
            "text": text,
            "final": state not in ACTIVE | {State.CREATED} and not input_only,
            "continue_required": waiting or input_only,
            "next_call": (
                {
                    "tool": "session_read",
                    "arguments": {
                        "pane_id": task["args"]["pane_id"],
                        "expected_pid": task["args"]["expected_pid"],
                    },
                }
                if input_only
                else {"tool": "task_get", "arguments": {"task_id": task["id"]}}
                if waiting
                else None
            ),
            "terminal_reply_tool": "session_read" if input_only else None,
            "scope": "terminal_input_delivery"
            if input_only
            else "addressed_agent_reply"
            if agent_reply
            else "task_execution_result",
            "delivery": "current_tool_response",
            "audio_playback": "not_observed_by_bridge",
        },
    }
    # Record what was prepared. The network peer and its speaker are outside this
    # function; recording this event must never create a "voice verified" badge.
    with bridge.store.transaction():
        bridge.store.audit(
            "conversation.response.prepared",
            principal,
            task["id"],
            {
                "state": state,
                "final": response["conversation_return"]["final"],
                "scope": response["conversation_return"]["scope"],
                "audio_playback": "not_observed_by_bridge",
            },
        )
    return response


async def message_for_conversation(bridge, principal, message):
    """Keep an addressed agent's answer on the requesting Grok voice turn."""
    if not enabled_for(bridge, principal) or "id" not in message:
        return message
    if message.get("transport") == "team":
        return message
    buffer = message.get("message_buffer")
    if buffer and buffer["state"] in {"waiting", "expired"}:
        return {
            **message,
            "conversation_return": {
                "text": "Diese alte Nachricht bleibt im historischen Puffer und wird nicht "
                "automatisch zugestellt. Neue ausdrückliche Aufträge benötigen kein Sondertoken."
                if buffer["state"] == "waiting"
                else "Die Nachricht ist verfallen und wurde nicht zugestellt.",
                "final": buffer["state"] == "expired",
                "continue_required": False,
                "next_call": None,
                "scope": "voice_message_buffer",
                "delivery": "current_tool_response",
                "audio_playback": "not_observed_by_bridge",
            },
        }
    channel = bridge.messages
    if message["recipient"] == principal and message["kind"] in {"answer", "result"}:
        return {
            **message,
            "conversation_return": {
                "text": message["body"],
                "final": True,
                "continue_required": False,
                "next_call": None,
                "scope": "addressed_agent_reply",
                "delivery": "current_tool_response",
                "audio_playback": "not_observed_by_bridge",
            },
        }
    deadline = asyncio.get_running_loop().time() + WAIT_SECONDS
    reply = None
    while True:
        message = channel.get(principal, message["id"])
        job = message.get("processing")
        if message["sender"] == principal:
            row = bridge.store.db.execute(
                "SELECT id FROM messages WHERE reply_to=? AND recipient=? AND sender=? "
                "ORDER BY seq LIMIT 1",
                (message["id"], principal, message["recipient"]),
            ).fetchone()
            if row:
                reply = channel.get(principal, row["id"])
                if reply["acknowledged"] is None:
                    delivered = channel.receive(
                        principal,
                        after=reply["seq"] - 1,
                        limit=1,
                        conversation_id=reply["conversation_id"],
                    )["messages"]
                    if delivered and delivered[0]["id"] == reply["id"]:
                        reply = delivered[0]
                break
        active = job and job["state"] in {"queued", "running"}
        waiting_reply = (
            message["sender"] == principal
            and message["request_reply"]
            and (not job or job["state"] not in MESSAGE_FAILURES)
        )
        if not (active or waiting_reply) or asyncio.get_running_loop().time() >= deadline:
            break
        await asyncio.sleep(0.05)

    job = message.get("processing")
    waiting = bool(
        not reply
        and (
            (job and job["state"] in {"queued", "running"})
            or (
                message["request_reply"]
                and message["sender"] == principal
                and (not job or job["state"] == "completed")
            )
        )
    )
    if reply:
        text, final = reply["body"], True
    elif job and job["state"] == "completed" and not message["request_reply"]:
        text, final = "Die Nachricht ist verarbeitet. Es war keine Antwort angefordert.", True
    elif job and job["state"] in MESSAGE_FAILURES:
        text = {
            State.FAILED: "Die Nachrichtenverarbeitung ist fehlgeschlagen.",
            State.UNKNOWN: (
                "Der Nachrichtenausgang ist unklar. Die Nachricht wird nicht erneut gesendet."
            ),
            State.BLOCKED: "Die Nachrichtenverarbeitung ist blockiert.",
            State.CANCELLED: "Die Nachrichtenverarbeitung wurde abgebrochen.",
        }[job["state"]]
        if job.get("error") == "delivery_retired_unresolved":
            text += (
                " Der ungeklärte Zustellungsversuch wurde stillgelegt. "
                "Sein früherer Ausgang bleibt unbestätigt."
            )
        final = True  # Final error report; never an addressed agent answer.
    else:
        evidence = (job or {}).get("evidence") or {}
        text, final = (
            evidence.get("waiting_message") or "Eine fertige Antwort liegt noch nicht vor.",
            False,
        )
    return {
        **message,
        "reply_message": reply,
        "conversation_return": {
            "text": text,
            "final": final,
            "continue_required": waiting,
            "next_call": {"tool": "message_get", "arguments": {"message_id": message["id"]}}
            if waiting
            else None,
            "scope": "addressed_agent_reply" if reply else "message_processing",
            "delivery": "current_tool_response",
            "audio_playback": "not_observed_by_bridge",
        },
    }
