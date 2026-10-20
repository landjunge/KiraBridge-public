"""Application queries for the local operator, without cross-module SQL.

Only the authenticated local operator surface uses these all-principal views.
Public MCP tools retain their existing owner-scoped permission checks.
"""

import time


class OperatorQueries:
    def __init__(self, tasks, messages, teams, audit, handoffs=None, output_history=None):
        self.tasks, self.messages, self.teams, self.audit = tasks, messages, teams, audit
        self.handoffs = handoffs
        self.output_history = output_history

    def maintenance_counts(self, *, active_only=False, context=None):
        return {
            name: owner.activation_work_count(active_only=active_only, context=context)
            for name, owner in (
                ("tasks", self.tasks),
                ("message_jobs", self.messages),
                ("team_work", self.teams),
                ("visible_handoffs", self.handoffs),
            )
        }

    def busy(self):
        # Keep the existing response keys for cached local clients. The values
        # are supplied by each domain owner, never inferred from OS 'busy'.
        return {
            "tasks": self.tasks.operator_work_count(),
            "message_jobs": self.messages.operator_work_count(),
            "team_work": self.teams.operator_work_count(),
        }

    def pending(self):
        return self.tasks.operator_pending()

    def recent_connection_checks(self):
        return self.audit.recent_connection_checks()

    def protocol(self, after=0, before=0):
        entries = []
        for row in self.audit.protocol_page(after, before):
            metadata = row["metadata"]
            entry = {key: row[key] for key in ("seq", "at", "kind", "principal", "task_id")}
            entry["details"] = metadata
            if (
                row["kind"] == "terminal.output"
                and metadata.get("output_ref")
                and self.output_history
            ):
                payload, status = self.output_history.read(row["principal"], metadata["output_ref"])
                entry["details"] = {
                    **metadata,
                    **(payload or {}),
                    "output_status": status,
                    "output_available": payload is not None,
                }
            if metadata.get("message_id"):
                message = self.messages.operator_protocol_snapshot(
                    metadata["message_id"], row["at"]
                )
                if message is not None:
                    entry["message"] = message
            if row["task_id"]:
                task = self.tasks.operator_snapshot_at(row["task_id"], row["at"])
                if task is not None:
                    entry["task"] = task
            entries.append(entry)
        return {
            "entries": entries,
            "last_seq": entries[-1]["seq"] if entries else after,
            "observed_at": time.time(),
        }
