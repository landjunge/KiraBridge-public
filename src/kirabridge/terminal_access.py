"""Explain granted terminal access separately from optional input confirmation."""

from kirabridge.permissions import decision


def terminal_access(config, principal):
    policy = config.principals[principal]
    caps = set(policy.capabilities)
    inspect = "session.inspect" in caps
    effective = decision(config, principal, "session.input")
    catalog_decision = decision(config, principal, "session.catalog")
    read_decision = decision(config, principal, "session.read")
    send = effective["authorized"]
    buffered = effective["buffer_enabled"]
    return {
        "policy_authorized": inspect and send,
        "discovery_allowed": inspect,
        "read_allowed": inspect,
        "catalog_decision": catalog_decision,
        "read_decision": read_decision,
        "read_approval_required": read_decision["approval_required"],
        "input_allowed": send,
        "input_approval_required": effective["approval_required"],
        "input_decision": effective,
        "additional_input_buffer_enabled": buffered,
        "session_input_policy_meaning": "optional_confirmation_buffer_not_terminal_enable_switch",
        "availability": "not_probed",
        "catalog_tool": "session_catalog",
        "read_tool": "session_read",
        "input_operation": "session.input",
        "cached_client_catalog_query": {"operation": "session.catalog"},
        "cached_client_task_operations": ["session.catalog", "session.read"],
        "cached_client_task_tool": "task_request",
        "cached_client_read_query": {
            "operation": "session.read",
            "pane_id": "FROM_CATALOG",
            "expected_pid": "FROM_CATALOG",
        },
        "description": (
            "Terminalrechte sind erteilt. Vorhandene Fenster über den Katalog auswählen; "
            "Lesen und Eingabe verwenden Fenster-ID, TTY und PID. "
            "Ein ausgeschalteter Zusatzpuffer deaktiviert den Terminalzugriff nicht."
            if inspect and send
            else "Terminalrechte sind nicht vollständig erteilt."
        ),
    }
