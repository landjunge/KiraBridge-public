from __future__ import annotations

import hashlib
import os
import sys
import tomllib
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from kirabridge.bridge_core.models import BridgeError


class PrincipalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approval_mode: Literal["manual", "automatic"] = "manual"
    capabilities: list[str] = Field(default_factory=lambda: ["bridge.health", "task.read"])
    roots: list[str] = Field(default_factory=list)
    read_roots: list[str] = Field(default_factory=list)
    executables: list[str] = Field(default_factory=list)
    allow_any_executable: bool = False
    terminal_roots: list[str] = Field(default_factory=list)
    agents: list[str] = Field(default_factory=list)
    token_env: str | None = None
    message_peers: list[str] = Field(default_factory=list, max_length=16)
    team_only_execution: bool = False
    permission_level: Literal["full", "medium", "ask"] | None = None
    automatic_operations: list[Literal["session.input"]] = Field(default_factory=list)


class ReceiverConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cwd: str
    timeout: float = Field(default=90, gt=0, le=300)


class MessagingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_body_bytes: int = Field(default=16384, ge=256, le=65536)
    max_pending_per_recipient: int = Field(default=100, ge=1, le=1000)
    max_total: int = Field(default=10000, ge=1, le=1000000)
    max_conversation_messages: int = Field(default=16, ge=2, le=128)
    max_reply_depth: int = Field(default=8, ge=1, le=32)
    max_runs_per_conversation: int = Field(default=4, ge=1, le=16)
    max_runs_per_hour: int = Field(default=24, ge=1, le=1000)
    receivers: dict[str, ReceiverConfig] = Field(default_factory=dict)


class TeamWorkerConfig(BaseModel):
    """Operator consent for one authenticated identity and its fixed executor."""

    model_config = ConfigDict(extra="forbid")
    agent: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{0,40}$")
    cwd: str | None = Field(default=None, min_length=1, max_length=4096)
    timeout: float = Field(default=120, gt=0, le=300)
    response_framing: Literal["strict_json", "work_reply_header"] = "strict_json"

    @model_validator(mode="after")
    def execution_directory(self):
        if self.agent is not None and (not self.cwd or not Path(self.cwd).is_absolute()):
            raise ValueError("An automatic team worker needs an absolute fixed working directory")
        return self


class TeamConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    workers: dict[str, TeamWorkerConfig] = Field(default_factory=dict, max_length=16)
    concurrency: int = Field(default=2, ge=1, le=8)
    max_teams: int = Field(default=64, ge=1, le=1024)
    max_hops: int = Field(default=6, ge=1, le=16)
    max_work_per_root: int = Field(default=32, ge=1, le=256)
    max_pending_per_member: int = Field(default=32, ge=1, le=1000)
    max_total_work: int = Field(default=10000, ge=1, le=1000000)
    max_messages: int = Field(default=10000, ge=1, le=1000000)
    max_body_bytes: int = Field(default=16384, ge=256, le=65536)
    max_result_bytes: int = Field(default=65536, ge=256, le=262144)
    max_actions_per_turn: int = Field(default=4, ge=1, le=4)
    max_runs_per_hour: int = Field(default=24, ge=1, le=1000)

    @model_validator(mode="after")
    def participant_names(self):
        import re

        if any(not re.fullmatch(r"[a-z][a-z0-9_-]{0,40}", name) for name in self.workers):
            raise ValueError("Team workers must use explicit principal identities")
        return self


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    executable: str | None = None
    model: str | None = None
    api_key_env: str = "XAI_API_KEY"
    sandbox_mode: Literal["read-only", "workspace-write", "danger-full-access"] = "read-only"
    bridge_tools: bool = False
    allow_local_tools: bool = False
    base_url: str | None = Field(default=None, max_length=2048)
    local_output_tokens: int | None = Field(default=None, ge=128, le=2048)

    @model_validator(mode="after")
    def explicit_full_access(self):
        if self.sandbox_mode == "danger-full-access" and not self.bridge_tools:
            raise ValueError("Full access requires the operator's explicit full bridge profile")
        return self

    @model_validator(mode="before")
    @classmethod
    def cli_credential_defaults(cls, value):
        defaults = {
            "opencode": "OPENCODE_API_KEY",
            "gemini_cli": "GEMINI_API_KEY",
            "claude_code": "ANTHROPIC_API_KEY",
            "copilot_cli": "COPILOT_GITHUB_TOKEN",
        }
        if (
            isinstance(value, dict)
            and isinstance(value.get("kind"), str)
            and value["kind"] in defaults
        ):
            return {"api_key_env": defaults[value["kind"]], **value}
        return value

    @model_validator(mode="after")
    def local_provider_endpoint(self):
        if self.local_output_tokens is not None and (self.kind != "opencode" or not self.base_url):
            raise ValueError("Local output tokens require a loopback OpenCode provider")
        if self.base_url is None:
            return self
        try:
            url = urlsplit(self.base_url)
            port = url.port
        except ValueError:
            raise ValueError("Invalid local model endpoint") from None
        if (
            self.kind != "opencode"
            or url.scheme not in {"http", "https"}
            or url.hostname not in {"127.0.0.1", "localhost", "::1"}
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or (port is not None and not 1 <= port <= 65535)
            or any(char.isspace() or ord(char) < 32 for char in self.base_url)
        ):
            raise ValueError("Only a credential-free loopback OpenCode endpoint is supported")
        return self


class DiagnosticsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    max_events_per_day: int = Field(default=2000, ge=10, le=100000)
    max_records: int = Field(default=20000, ge=10, le=1000000)


class ThreadDeskConfig(BaseModel):
    """Operator-owned local endpoint; requests cannot select a process or store."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    command: str | None = None
    args: list[str] = Field(default_factory=list, max_length=32)
    workspace: str | None = None
    source_root: str | None = None
    storage: Literal["json", "sqlite"] = "json"
    timeout: float = Field(default=15, gt=0, le=60)
    max_result_bytes: int = Field(default=524288, ge=1024, le=1048576)


class WorkflowControlConfig(BaseModel):
    """Explicit operator-owned CLI stop scope; never a hard money budget."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    mode: Literal["stop_only"] = "stop_only"
    state_root: str | None = None
    projects: dict[str, list[str]] = Field(default_factory=dict, max_length=32)
    actor_id: str = Field(default="kirabridge-cli", pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    consumer_id: str = Field(default="kirabridge-cli", pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    source_commit: str | None = Field(default=None, pattern=r"^[a-f0-9]{40}$")
    source_package_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class TerminalConfig(BaseModel):
    """Operator-owned tool discovery; never inherit the daemon's secret environment."""

    model_config = ConfigDict(extra="forbid")
    search_path: list[str] = Field(default_factory=list, max_length=32)
    home: str | None = None


class GrokConnectorConfig(BaseModel):
    """Separate OAuth entry point for the Grok application, never its CLI identity."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    public_origin: str | None = Field(default=None, max_length=2048)
    principal: Literal["grok_app"] = "grok_app"
    port: int = Field(default=8767, ge=1024, le=65535)
    redirect_hosts: list[str] = Field(
        default_factory=lambda: ["grok.com", "accounts.x.ai", "console.x.ai"],
        min_length=1,
        max_length=16,
    )
    max_requests: int = Field(default=16, ge=1, le=64)
    max_body_bytes: int = Field(default=2097152, ge=1024, le=8388608)

    @model_validator(mode="after")
    def external_identity(self):
        import re

        if any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", h) or ".." in h or "." not in h
            for h in self.redirect_hosts
        ):
            raise ValueError("Use exact HTTPS callback host names, without wildcard or path")
        if self.public_origin is not None:
            if (
                any(c.isspace() or ord(c) < 32 for c in self.public_origin)
                or "?" in self.public_origin
                or "#" in self.public_origin
            ):
                raise ValueError(
                    "Use a canonical HTTPS origin without query, fragment or whitespace"
                )
            parsed = urlsplit(self.public_origin)
            _ = parsed.port  # Validate port syntax before starting a supervised service.
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
                or parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            ):
                raise ValueError(
                    "Grok connector needs a public HTTPS origin without credentials or path"
                )
            self.public_origin = self.public_origin.rstrip("/")
        if self.enabled and not self.public_origin:
            raise ValueError("An enabled Grok connector needs its public HTTPS origin")
        return self


class SessionInputPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    timeout_seconds: float = Field(default=60, gt=0, le=86400)
    principals: list[str] = Field(default_factory=list)


class VoiceMessagingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Retired by Daniel: updates cannot re-enable the extra voice approval gate.
    release_required: Literal[False] = False
    timeout_seconds: float = Field(default=60, gt=0, le=86400)


class VoiceChannelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    conversation_id: str = Field(default="eve-kira-shared", pattern=r"^[\w-]{1,128}$")


class VisibleTerminalBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pane_id: str = Field(pattern=r"^terminal:[0-9]+:ttys[0-9]+$")
    expected_pid: int = Field(gt=0)
    agent_pid: int = Field(gt=0)
    ready_pattern: str = Field(min_length=1, max_length=256)
    busy_pattern: str = Field(default=r"\[stop\]|esc to interrupt|Thinking…", max_length=256)
    codex_thread_id: str | None = Field(default=None, pattern=r"^[0-9a-f-]{36}$")
    codex_rollout_path: str | None = Field(default=None, min_length=1, max_length=4096)

    @model_validator(mode="after")
    def protocol_pair(self):
        if bool(self.codex_thread_id) != bool(self.codex_rollout_path):
            raise ValueError("Codex protocol path and thread must be bound together")
        return self


class VisibleHandoffConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: Literal[True] = True
    bindings: dict[str, VisibleTerminalBinding] = Field(default_factory=dict)


class OutputHistoryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_bytes: int = Field(default=16777216, ge=4096, le=1073741824)
    max_entries: int = Field(default=256, ge=1, le=100000)
    max_item_bytes: int = Field(default=8388608, ge=1024, le=8388608)
    retention_seconds: float = Field(default=604800, ge=60, le=31536000)


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    _source_path: str | None = PrivateAttr(default=None)
    _source_sha256: str | None = PrivateAttr(default=None)
    _effective_sha256: str | None = PrivateAttr(default=None)
    data_dir: str = str(Path.home() / ".local/share/kirabridge")
    concurrency: int = Field(default=2, ge=1, le=32)
    max_queued: int = Field(default=1000, ge=1, le=100000)
    max_control_queued: int = Field(default=32, ge=1, le=1000)
    max_read_queued: int = Field(default=32, ge=1, le=1000)
    read_concurrency: int = Field(default=2, ge=1, le=8)
    max_task_bytes: int = Field(default=2097152, ge=1024, le=8388608)
    output_history: OutputHistoryConfig = Field(default_factory=OutputHistoryConfig)
    lease_seconds: float = Field(default=30, ge=2, le=600)
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)
    allow_remote: bool = False
    credentials_file: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "[::1]"])
    allowed_origins: list[str] = Field(default_factory=list)
    max_http_requests: int = Field(default=32, ge=1, le=256)
    principals: dict[str, PrincipalConfig] = Field(
        default_factory=lambda: {"local": PrincipalConfig()}
    )
    agents: dict[str, AgentConfig] = Field(default_factory=dict)
    messaging: MessagingConfig = Field(default_factory=MessagingConfig)
    team: TeamConfig = Field(default_factory=TeamConfig)
    grok_connector: GrokConnectorConfig = Field(default_factory=GrokConnectorConfig)
    diagnostics: DiagnosticsConfig = Field(default_factory=DiagnosticsConfig)
    threaddesk: ThreadDeskConfig = Field(default_factory=ThreadDeskConfig)
    workflow_control: WorkflowControlConfig = Field(default_factory=WorkflowControlConfig)
    session_input_policy: SessionInputPolicyConfig = Field(default_factory=SessionInputPolicyConfig)
    voice_messaging: VoiceMessagingConfig = Field(default_factory=VoiceMessagingConfig)
    voice_channel: VoiceChannelConfig = Field(default_factory=VoiceChannelConfig)
    visible_handoffs: VisibleHandoffConfig = Field(default_factory=VisibleHandoffConfig)

    terminal: TerminalConfig = Field(default_factory=TerminalConfig)

    @property
    def state_path(self) -> Path:
        return Path(self.data_dir).expanduser().absolute()

    def validate_network(self) -> None:
        local = self.host in {"127.0.0.1", "::1", "localhost"}
        if not local and not (self.allow_remote and self.tls_cert and self.tls_key):
            raise BridgeError(
                "unsafe_bind", "Remote binding requires allow_remote and TLS cert/key"
            )
        if bool(self.tls_cert) != bool(self.tls_key):
            raise BridgeError("tls_config", "Configure both TLS certificate and key")
        if not any(p.token_env for p in self.principals.values()):
            raise BridgeError("auth_config", "HTTP requires a configured bearer token environment")
        tokens = [os.environ.get(p.token_env, "") for p in self.principals.values() if p.token_env]
        if any(len(t) < 32 for t in tokens) or len(set(tokens)) != len(tokens):
            raise BridgeError(
                "auth_config", "HTTP tokens must be unique and at least 32 characters"
            )


def load_config(path: str | None = None) -> Config:
    path = path or os.environ.get("KIRABRIDGE_CONFIG")
    default = Path.home() / ".config/kirabridge/config.toml"
    if path is None and default.is_file():
        path = str(default)
    if path:
        source_path = Path(path).expanduser().absolute()
        raw = source_path.read_bytes()
        config = Config.model_validate(tomllib.loads(raw.decode("utf-8")))
        config._source_path = str(source_path)
        config._source_sha256 = hashlib.sha256(raw).hexdigest()
        from kirabridge.bridge_core.models import digest

        config._effective_sha256 = digest(config.model_dump())
        return config
    return Config()


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise BridgeError("unsafe_state", "State directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if sys.platform != "win32":
        if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
            raise BridgeError("unsafe_state", "State directory must be owner-only (chmod 700)")
