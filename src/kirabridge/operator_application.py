"""Composition root for the trusted local operator, never exposed as an MCP tool."""

from dataclasses import dataclass

from kirabridge.audit_manager import AuditReader, AuditWriter
from kirabridge.bridge_core.config import load_config
from kirabridge.grok_connector.administration import ConnectorAdministration
from kirabridge.operations_service import OperationsService
from kirabridge.operator_actions import (
    ControlActionRepository,
    ControlActions,
    OperatorTaskDecisions,
)
from kirabridge.operator_control import OperatorControl
from kirabridge.operator_platform import LocalDaemonClient, LocalProcessPlatform
from kirabridge.operator_queries import OperatorQueries


class OperatorConfiguration:
    def __init__(self, config):
        self.loaded = config

    def __call__(self):
        path = self.loaded._source_path
        return load_config(path) if path else self.loaded


@dataclass(frozen=True)
class TeamOperatorPorts:
    config: object
    security: object
    teams: object


@dataclass(frozen=True)
class OperatorApplication:
    control: OperatorControl
    task_decisions: OperatorTaskDecisions
    audit: AuditWriter
    team: TeamOperatorPorts
    connectors: ConnectorAdministration
    authorize_operator: object


def operator_application(bridge):
    """Only this composition boundary knows the complete core."""
    config = OperatorConfiguration(bridge.config)
    audit = AuditWriter(bridge.store)
    connectors = ConnectorAdministration(config)
    queries = OperatorQueries(
        bridge.store,
        bridge.messages,
        bridge.teams,
        AuditReader(bridge.store),
        bridge.visible_handoffs,
        bridge.outputs,
    )
    control = OperatorControl(
        config=config,
        queries=queries,
        daemon=LocalDaemonClient(config),
        platform=LocalProcessPlatform(),
        actions=ControlActions(ControlActionRepository(bridge.store)),
        maintenance=bridge.store.maintenance_state,
        grant_window=bridge.security.grant_window,
        audit=audit,
        connectors=connectors,
    )
    control.operations = OperationsService(
        bridge.store,
        lambda: control.config(),
        lambda *args, **kwargs: control.rpc(*args, **kwargs),
        lambda *args, **kwargs: control.command(*args, **kwargs),
        bridge.runtime,
        work_queries=queries.maintenance_counts,
    )
    authorize_principal = bridge.security.principal
    return OperatorApplication(
        control,
        OperatorTaskDecisions(bridge.tasks, bridge.store, config),
        audit,
        TeamOperatorPorts(bridge.config, bridge.security, bridge.teams),
        connectors,
        lambda: authorize_principal("local"),
    )
