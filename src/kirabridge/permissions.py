"""The three operator permission levels, shared by every authenticated entry point."""

from __future__ import annotations

from kirabridge.bridge_core.config import PrincipalConfig
from kirabridge.bridge_core.models import digest
from kirabridge.operations import READ_OPERATIONS, capability_for

LEVELS = {"full": "Voll erlaubt", "medium": "Mittel", "ask": "Nur mit Erlaubnis"}


def level_for(policy: PrincipalConfig) -> str:
    if policy.permission_level:
        return policy.permission_level
    if policy.approval_mode == "manual":
        return "ask"
    return "full" if policy.allow_any_executable and "/" in policy.roots else "medium"


def automatic_for(policy: PrincipalConfig, operation: str) -> bool:
    if operation in policy.automatic_operations:
        return True
    # Existing policies retain their exact behavior until the operator selects a level.
    if policy.permission_level is None:
        return policy.approval_mode == "automatic"
    return policy.permission_level == "full" or (
        policy.permission_level == "medium" and operation in READ_OPERATIONS
    )


def permission_revision(config):
    """Explicit authorization whitelist; never serialize credentials in status paths."""
    fields = (
        "capabilities",
        "permission_level",
        "approval_mode",
        "automatic_operations",
        "roots",
        "read_roots",
        "executables",
        "allow_any_executable",
        "terminal_roots",
        "agents",
        "message_peers",
        "team_only_execution",
    )
    return digest(
        {
            "principals": {
                name: {field: getattr(policy, field) for field in fields}
                for name, policy in config.principals.items()
            },
            "session_input_policy": {
                "enabled": config.session_input_policy.enabled,
                "principals": config.session_input_policy.principals,
                "timeout_seconds": config.session_input_policy.timeout_seconds,
            },
        }
    )


def decision(config, principal, operation, *, text=None):
    """One effective policy decision; never substitutes an exception for a capability.

    No filesystem reads: the revision identifies the configuration actually used
    by this process. A missing text reports whether an input would need buffering.
    Exact-task approvals and persisted historical buffers remain separate evidence.
    """
    policy = config.principals.get(principal)
    required = {capability_for(operation)}
    if operation == "session.input":
        required.update({"session.inspect", "terminal.execute"})
    missing = sorted(required - set(policy.capabilities if policy else []))
    exception = bool(policy and operation in policy.automatic_operations)
    gate = config.session_input_policy
    buffered = bool(
        policy
        and operation == "session.input"
        and gate.enabled
        and principal in gate.principals
        and not exception
    )
    # This is the optional terminal buffer, not the retired Kira/Eve voice gate.
    from kirabridge.session_input_policy import marked

    held = buffered and (text is None or not marked(text))
    automatic = bool(policy and not missing and automatic_for(policy, operation) and not held)
    reason = (
        "missing_capability"
        if missing
        else "terminal_confirmation_buffer"
        if held
        else "standing_operation_grant"
        if exception
        else "level_automatic"
        if automatic
        else "user_approval_required"
    )
    return {
        "principal": principal,
        "operation": operation,
        "authorized": not missing,
        "automatic": automatic,
        "approval_required": not missing and not automatic,
        "reason": reason,
        "missing_capabilities": missing,
        "standing_exception": exception,
        "buffer_enabled": buffered,
        "buffer_required": held,
        "permission_level": level_for(policy) if policy else None,
        "config_revision": config._effective_sha256,
        "permission_revision": permission_revision(config),
        "config_file_sha256": config._source_sha256,
    }


def permission_summary(config, principal):
    policy = config.principals[principal]
    exceptions = [decision(config, principal, op) for op in policy.automatic_operations]
    label = LEVELS[level_for(policy)]
    if exceptions:
        label += " · dauerhafte Ausnahme: Terminaleingabe"
    return {
        "label": label,
        "exceptions": exceptions,
        "config_revision": config._effective_sha256,
        "permission_revision": permission_revision(config),
    }


def state_exclusions(config, policy):
    explicit_full_grant = (
        policy.permission_level is not None and policy.allow_any_executable and "/" in policy.roots
    )
    return [] if explicit_full_grant else [str(config.state_path)]
