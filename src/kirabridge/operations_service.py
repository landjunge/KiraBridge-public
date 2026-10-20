"""Local configuration ownership and coordinated, durable core activation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path

from kirabridge.bridge_core.config import load_config, private_directory
from kirabridge.bridge_core.models import BridgeError, canonical, digest
from kirabridge.grok_connector.runtime import replace_private
from kirabridge.local_runtime import write_private
from kirabridge.permissions import LEVELS
from kirabridge.task_manager.store import SCHEMA_VERSION


def replace_section(text, header, values):
    body = (
        "\n["
        + header
        + "]\n"
        + "".join(
            key + " = " + json.dumps(value, ensure_ascii=False) + "\n"
            for key, value in values.items()
            if value is not None
        )
    )
    pattern = r"(?ms)^\[" + re.escape(header) + r"\][^\n]*\n.*?(?=^\[|\Z)"
    if re.search(pattern, text):
        return re.sub(pattern, lambda _: body.lstrip("\n"), text, count=1)
    return text.rstrip() + "\n" + body


def access_text(config_path: Path, *, level=None, revoke_operations=None):
    """Keep credentials and existing grants. The full level uses the operator's full grant."""
    from kirabridge.bridge_core.bridge import INPUTS

    config = load_config(str(config_path))
    if level is not None and level not in LEVELS:
        raise BridgeError("invalid_request", "Wähle eine der drei Rechtestufen")
    revoke_operations = revoke_operations or {}
    if not isinstance(revoke_operations, dict) or any(
        name not in config.principals
        or not isinstance(operations, list)
        or any(op != "session.input" for op in operations)
        for name, operations in revoke_operations.items()
    ):
        raise BridgeError("invalid_request", "Ungültiger Widerruf einer dauerhaften Ausnahme")
    text = config_path.read_text()
    names = list(config.principals)
    if len(names) > 17:
        raise BridgeError("peer_capacity", "Mehr Teilnehmer als die Postfachkapazität erlaubt")
    for name, policy in config.principals.items():
        policy.automatic_operations = [
            op for op in policy.automatic_operations if op not in revoke_operations.get(name, [])
        ]
        policy.message_peers = [other for other in names if other != name]
        policy.capabilities = list(
            dict.fromkeys(
                policy.capabilities
                + [
                    "message.send",
                    "connection.check",
                    "message.read",
                    "message.ack",
                    "session.inspect",
                    "session.input",
                    "session.open",
                    "team.read",
                    "team.write",
                ]
            )
        )
        if level:
            policy.permission_level = level
            policy.approval_mode = "manual" if level == "ask" else "automatic"
        if level == "full":
            policy.capabilities = list(
                dict.fromkeys(
                    policy.capabilities
                    + list(INPUTS)
                    + [
                        "bridge.health",
                        "task.read",
                        "task.cancel",
                        "agent.inspect",
                        "team.manage",
                        "agent.local_tools",
                    ]
                )
            )
            policy.roots = policy.read_roots = policy.terminal_roots = ["/"]
            policy.allow_any_executable = True
            policy.team_only_execution = False
            policy.agents = list(config.agents)
        text = replace_section(text, "principals." + name, policy.model_dump())
    for name, profile in config.agents.items():
        if level == "full":
            profile.allow_local_tools = True
            profile.bridge_tools = True
            if profile.kind == "codex":
                profile.sandbox_mode = "danger-full-access"
            text = replace_section(text, "agents." + name, profile.model_dump())
    # Every installed worker gets an inbox. App identities are consumers, not spawned models.
    for name in config.agents:
        if name in config.principals and name not in config.messaging.receivers:
            directory = config_path.parent / "workers" / name
            text = replace_section(
                text, "messaging.receivers." + name, {"cwd": str(directory), "timeout": 180.0}
            )
    # Validate before replacing. The operator's existing credentials are never rotated.
    import tomllib

    from kirabridge.bridge_core.config import Config

    Config.model_validate(tomllib.loads(text))
    return text


def configure_access(config_path: Path, *, level=None, revoke_operations=None):
    """Compatibility for explicit local administration; UI uses OperationsService."""
    text = access_text(config_path, level=level, revoke_operations=revoke_operations)
    if text != config_path.read_text():
        folder = config_path.parent / "backups"
        private_directory(folder)
        write_private(folder / ("control-" + uuid.uuid4().hex + ".toml"), config_path.read_bytes())
        replace_private(config_path, text)
    return load_config(str(config_path))


def installed_source_sha():
    root = Path(__file__).parent
    return digest(
        {
            str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*.py"))
        }
    )


def config_snapshot(config):
    """Private immutable config copy; no raw configuration is put in audit/SQL."""
    if not config._source_path or not config._source_sha256:
        return None
    raw = Path(config._source_path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != config._source_sha256:
        raise BridgeError("config_changed", "Configuration changed during loading")
    folder = config.state_path / "activation-configs"
    private_directory(folder)
    path = folder / (config._source_sha256 + ".toml")
    try:
        write_private(path, raw)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != raw:
            raise BridgeError(
                "activation_snapshot_conflict", "Inspect preserved configuration"
            ) from None
    return path


class OperationsService:
    """Trusted local operator service. Not exposed as an MCP grant issuer.

    New submissions stop at a durable barrier. Already queued/owned work drains
    under that barrier. No await, process or network call holds a write transaction.
    Crashed controllers leave the barrier for explicit local recovery.
    """

    def __init__(self, store, config_provider, rpc, command, runtime, *, work_queries):
        self.store, self.config = store, config_provider
        self.rpc, self.command = rpc, command
        self.work_queries = work_queries
        self.source_sha = runtime["source_tree_sha256"]
        self.version = runtime["version"]
        self.drain_timeout = 30.0
        self.state_path = Path(store.db.execute("PRAGMA database_list").fetchone()[2]).parent

    def check_source(self):
        if installed_source_sha() != self.source_sha:
            raise BridgeError(
                "stale_control_process",
                "Das Steuerfenster verwendet alte Dateien. "
                "Bitte das Steuerfenster neu starten; laufende Agenten bleiben erhalten.",
            )

    def work_counts(self, *, active_only=False):
        # Domain owners issue their SQL using this same transaction context.
        # The runtime service knows no foreign table or foreign state machine.
        return self.work_queries(active_only=active_only, context=self.store)

    def update(self, identifier, state, error=None):
        with self.store.transaction():
            self.store.db.execute(
                "UPDATE activation_runs SET state=?,updated=?,error=? WHERE id=?",
                (state, time.time(), error, identifier),
            )
            self.store.audit(
                "activation." + state, "local", None, {"activation_id": identifier, "error": error}
            )

    def prior_text(self, config, health):
        expected = health["runtime"]["config_sha256"]
        path = config.state_path / "activation-configs" / (str(expected) + ".toml")
        if expected == config._source_sha256:
            path = config_snapshot(config)
        if not path or not path.is_file() or path.is_symlink():
            raise BridgeError(
                "activation_prior_config_missing", "Die zuvor geladene Konfiguration fehlt"
            )
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise BridgeError(
                "activation_snapshot_conflict", "Der vorherige Konfigurationsbeleg ist verändert"
            )
        return raw.decode()

    async def configure(self, *, level=None, revoke_operations=None):
        config = self.config()
        return await self.activate(
            text=access_text(
                Path(config._source_path), level=level, revoke_operations=revoke_operations
            ),
            expected_config_sha=config._source_sha256,
        )

    async def verify(self, *, config_sha, effective_sha, previous_instance):
        for _ in range(20):
            try:
                health = await self.rpc("bridge_health", timeout=2)
                runtime = health.get("runtime", {})
                if (
                    health.get("dispatcher_active")
                    and runtime.get("instance_id") != previous_instance
                    and runtime.get("version") == self.version
                    and runtime.get("source_tree_sha256") == self.source_sha
                    and runtime.get("config_sha256") == config_sha
                    and runtime.get("effective_config_sha256") == effective_sha
                ):
                    return health
            except Exception:
                pass
            await asyncio.sleep(0.2)
        raise BridgeError(
            "activation_unconfirmed", "Neustart und geladener Stand sind nicht bestätigt"
        )

    async def restart(self, identifier):
        # Enforce the durable reservation even for another internal caller.
        if self.store.db.in_transaction:
            raise BridgeError("activation_transaction", "Restart cannot hold a write transaction")
        with self.store.transaction():
            row = self.store.db.execute(
                "SELECT state,plan FROM activation_runs WHERE id=?", (identifier,)
            ).fetchone()
            if (
                not row
                or row["state"] not in {"verifying", "recovering"}
                or json.loads(row["plan"]).get("owner_pid") != os.getpid()
            ):
                raise BridgeError(
                    "activation_ownership_required", "Keine eigene aktive Neustartreservierung"
                )
            if any(self.work_counts(active_only=row["state"] == "recovering").values()):
                raise BridgeError("service_busy", "Laufende Arbeit bleibt erhalten")
        code, _, _ = await self.command(
            "/bin/launchctl", "kickstart", "-k", f"gui/{os.getuid()}/com.kirabridge.bridge"
        )
        if code:
            raise BridgeError("service_restart", "KiraBridge konnte nicht neu gestartet werden")

    async def activate(self, *, text=None, expected_config_sha=None):
        self.check_source()
        config = self.config()
        if not config._source_path:
            raise BridgeError(
                "config_required", "Eine konkrete Konfigurationsdatei ist erforderlich"
            )
        import tomllib

        from pydantic import ValidationError

        from kirabridge.bridge_core.config import Config

        path = Path(config._source_path)
        before = path.read_text()
        if (
            hashlib.sha256(before.encode()).hexdigest() != config._source_sha256
            or expected_config_sha is not None
            and expected_config_sha != config._source_sha256
        ):
            raise BridgeError(
                "config_changed", "Gleichzeitig geänderte Einstellungen bleiben erhalten"
            )
        text = before if text is None else text
        try:
            candidate = Config.model_validate(tomllib.loads(text))
        except (ValueError, ValidationError):
            raise BridgeError("invalid_config", "Die neuen Einstellungen sind ungültig") from None
        target_sha, effective = (
            hashlib.sha256(text.encode()).hexdigest(),
            digest(candidate.model_dump()),
        )
        if candidate.state_path != self.state_path or config.state_path != self.state_path:
            raise BridgeError(
                "activation_state_move",
                "Datenverzeichnis separat migrieren; keine automatische Rückkehr",
            )
        health = await self.rpc("bridge_health", timeout=2)
        if health.get("operations", {}).get("protocol") != 1:
            raise BridgeError(
                "activation_upgrade_required",
                "Zuerst den koordinierten Betriebsdienst installieren",
            )
        prior = self.prior_text(config, health)
        previous_sha = hashlib.sha256(prior.encode()).hexdigest()
        previous_effective = digest(Config.model_validate(tomllib.loads(prior)).model_dump())
        if self.store.db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise BridgeError(
                "activation_schema_plan_required",
                "Schemaänderung benötigt einen eigenen Rückkehrplan",
            )
        identifier = "activation-" + uuid.uuid4().hex
        plan = {
            "owner_pid": os.getpid(),
            "config_path": str(path),
            "before_sha": previous_sha,
            "disk_before_sha": hashlib.sha256(before.encode()).hexdigest(),
            "target_sha": target_sha,
            "target_effective_sha": effective,
            "previous_effective_sha": previous_effective,
            "previous_instance": health["runtime"]["instance_id"],
            "source_sha": self.source_sha,
            "version": self.version,
            "schema": SCHEMA_VERSION,
        }
        with self.store.transaction():
            self.store.assert_accepting()
            now = time.time()
            self.store.db.execute(
                "INSERT INTO activation_runs VALUES(?,?,?,?,?,NULL)",
                (identifier, "draining", now, now, canonical(plan)),
            )
            self.store.audit(
                "activation.draining", "local", None, {"activation_id": identifier, "plan": plan}
            )
        changed = False
        try:
            deadline = time.monotonic() + self.drain_timeout
            while any(self.work_counts().values()):
                if time.monotonic() >= deadline:
                    raise BridgeError(
                        "service_busy",
                        "Ein Auftrag läuft oder wartet. Aktivierung später erneut versuchen.",
                    )
                await asyncio.sleep(0.05)
            with self.store.transaction():
                if any(self.work_counts().values()):
                    raise BridgeError("service_busy", "Ein Auftrag läuft noch")
                self.update(identifier, "activating")
            self.check_source()
            if path.read_text() != before:
                raise BridgeError(
                    "config_changed", "Gleichzeitig geänderte Einstellungen bleiben erhalten"
                )
            replace_private(path, text)
            changed = True
            self.update(identifier, "verifying")
            await self.restart(identifier)
            result = await self.verify(
                config_sha=target_sha,
                effective_sha=effective,
                previous_instance=plan["previous_instance"],
            )
            self.update(identifier, "completed")
            return {
                **result,
                "activation_id": identifier,
                "operations": {"protocol": 1, "maintenance": None, "accepting_new_work": True},
            }
        except BaseException as exc:
            if changed:
                self.update(
                    identifier, "failed_blocked", getattr(exc, "code", "controller_interrupted")
                )
                # Restoring bytes is safe only for our exact file transition and
                # unchanged schema. Recovery performs and verifies a new core start.
                if (
                    self.store.db.execute("PRAGMA user_version").fetchone()[0] == plan["schema"]
                    and hashlib.sha256(path.read_bytes()).hexdigest() == target_sha
                ):
                    replace_private(path, prior)
            else:
                self.update(identifier, "failed", getattr(exc, "code", "controller_interrupted"))
            raise

    async def recover(self):
        """Explicit local doctor action; never restore a DB or repeat terminal input."""
        self.check_source()
        with self.store.transaction():
            state = self.store.maintenance_state()
            if not state:
                return None
            row = self.store.db.execute(
                "SELECT plan FROM activation_runs WHERE id=?", (state["id"],)
            ).fetchone()
            plan = json.loads(row[0])
            # Another live controller must not be raced. Interrupted drains need
            # operator diagnosis until their recorded owner is known to be gone.
            if state["state"] != "failed_blocked":
                owner = plan.get("owner_pid")
                alive = True
                if isinstance(owner, int) and owner > 1 and os.name == "posix":
                    try:
                        os.kill(owner, 0)
                    except ProcessLookupError:
                        alive = False
                if alive:
                    raise BridgeError(
                        "activation_in_progress",
                        "Aktivierung läuft oder ihr Besitzer ist noch vorhanden; "
                        "keine zweite starten",
                    )
            if any(self.work_counts(active_only=True).values()):
                raise BridgeError("service_busy", "Laufende Arbeit bleibt erhalten")
            plan["owner_pid"] = os.getpid()
            self.store.db.execute(
                "UPDATE activation_runs SET plan=? WHERE id=?",
                (canonical(plan), state["id"]),
            )
            self.update(state["id"], "recovering")
        try:
            if self.store.db.execute("PRAGMA user_version").fetchone()[0] != plan["schema"]:
                raise BridgeError(
                    "activation_schema_plan_required", "Schema-Rückkehr muss gesondert erfolgen"
                )
            if any(self.work_counts(active_only=True).values()):
                raise BridgeError("service_busy", "Laufende Arbeit bleibt erhalten")
            path = Path(plan["config_path"])
            if hashlib.sha256(path.read_bytes()).hexdigest() not in {
                plan["before_sha"],
                plan["target_sha"],
                plan["disk_before_sha"],
            }:
                raise BridgeError(
                    "config_changed", "Unbekannte Konfigurationsänderung bleibt erhalten"
                )
            previous = self.state_path / "activation-configs" / (plan["before_sha"] + ".toml")
            raw = previous.read_bytes()
            if hashlib.sha256(raw).hexdigest() != plan["before_sha"]:
                raise BridgeError(
                    "activation_snapshot_conflict", "Vorheriger Konfigurationsbeleg verändert"
                )
            replace_private(path, raw.decode())
            await self.restart(state["id"])
            result = await self.verify(
                config_sha=plan["before_sha"],
                effective_sha=plan["previous_effective_sha"],
                previous_instance=plan["previous_instance"],
            )
            self.update(state["id"], "recovered")
            return {
                **result,
                "recovery_id": state["id"],
                "operations": {"protocol": 1, "maintenance": None, "accepting_new_work": True},
            }
        except BaseException as exc:
            self.update(state["id"], "failed_blocked", getattr(exc, "code", "recovery_interrupted"))
            raise
