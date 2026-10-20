from __future__ import annotations

import asyncio
import time
import uuid
from typing import Awaitable, Callable

from kirabridge.bridge_core.config import Config
from kirabridge.bridge_core.models import (
    BridgeError,
    State,
    TaskRequest,
    UncertainExecution,
    canonical,
    digest,
)
from kirabridge.operations import OPERATIONS
from kirabridge.platform_adapters import RuntimeLock
from kirabridge.security_manager import SecurityManager, request_hash
from kirabridge.task_manager.store import Store

Executor = Callable[[dict, Callable, Callable], Awaitable[dict]]


class TaskManager:
    def __init__(
        self,
        config: Config,
        store: Store,
        security: SecurityManager,
        executor: Executor,
        preflight=None,
        runtime=None,
    ):
        self.config, self.store, self.security, self.executor = config, store, security, executor
        self.owner = str(uuid.uuid4())
        self.lock = RuntimeLock(config.state_path / "dispatcher.lock.runtime")
        self.workers: list[asyncio.Task] = []
        self.wake = asyncio.Event()
        self.preflight = preflight
        self.runtime = runtime
        self.maintenance = None
        from kirabridge.session_input_policy import SessionInputPolicy

        self.input_policy = SessionInputPolicy(config, store, security)

    def enqueue(
        self,
        principal: str,
        request: TaskRequest,
        approval: str,
        *,
        attempt: int = 1,
        pending: bool = False,
        completion_target: str | None = None,
    ) -> dict:
        from kirabridge.completion_manager import valid_target

        if completion_target is not None:
            valid_target(completion_target)
        policy = self.security.principal(principal, request.operation)
        effective = self.security.authorize(
            principal, request.operation, text=request.arguments.get("text")
        )
        automatic = effective["automatic"] and not approval
        pending = pending and not automatic
        self.input_policy.expire()
        buffered = effective["buffer_enabled"]
        held = effective["buffer_required"]
        if held:
            pending = True
        if request.api_version != "1":
            raise BridgeError("api_version", "Unsupported API version")
        if len(canonical(request.model_dump()).encode()) > self.config.max_task_bytes:
            raise BridgeError("payload_limit", "Task exceeds configured byte limit")
        with self.store.transaction():
            existing = self.store.db.execute(
                "SELECT id,request_hash FROM tasks WHERE principal=? AND idem=?",
                (principal, request.idempotency_key),
            ).fetchone()
            if existing:
                if existing["request_hash"] != request_hash(request):
                    raise BridgeError(
                        "idempotency_conflict", "Idempotency key belongs to a different request"
                    )
                route = self.store.db.execute(
                    "SELECT target FROM completion_routes WHERE task_id=?", (existing["id"],)
                ).fetchone()
                if completion_target is not None and completion_target != (
                    route[0] if route else "default"
                ):
                    raise BridgeError(
                        "completion_route_conflict", "Original return target is fixed"
                    )
                if approval and self.input_policy.waiting(existing["id"]):
                    self.store.assert_accepting()
                    if request.task_id != existing["id"]:
                        raise BridgeError("review_conflict", "Use the original buffered task ID")
                    self.input_policy.release(principal, request, approval)
                    self._approve_in_transaction(existing["id"], "daniel_token")
                    self.wake.set()
                return self.store.get(existing["id"], principal)
            self.store.assert_accepting(
                continuation_id=request.task_id,
                principal=principal,
                request_hash=request_hash(request),
                operation=request.operation,
            )
            if self.store.db.execute(
                "SELECT 1 FROM tasks WHERE id=?", (request.task_id,)
            ).fetchone():
                raise BridgeError("task_id_conflict", "Task identifier is already reserved")
            lane = OPERATIONS[request.operation].execution_class
            count = self.store.queued_count(lane)
            capacity = {
                "normal": self.config.max_queued,
                "read": self.config.max_read_queued,
                "stop": self.config.max_control_queued,
            }[lane]
            if count >= capacity:
                raise BridgeError("queue_full", "Queue capacity reached")
            effective_target = completion_target or "default"
            if request.parent_id:
                if completion_target is None:
                    route = self.store.db.execute(
                        "SELECT target FROM completion_routes WHERE task_id=?", (request.parent_id,)
                    ).fetchone()
                    effective_target = route[0] if route else "default"
                parent = self.store.get(request.parent_id, principal)
                depth = 1
                while parent["parent_id"]:
                    depth += 1
                    if depth >= 32:
                        raise BridgeError("delegation_limit", "Delegation chain exceeds 32 tasks")
                    parent = self.store.get(parent["parent_id"], principal)
            if request.operation == "session.open":
                from kirabridge.session_manager import SessionOpen

                self.security.consume_window(
                    principal, request.task_id, SessionOpen.model_validate(request.arguments)
                )
            if not pending and not automatic:
                self.security.consume(principal, request, approval)
            now = time.time()
            self.store.db.execute(
                "INSERT INTO tasks(id,principal,idem,request_hash,operation,args,agent,parent_id,"
                "state,created,updated,attempt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    request.task_id,
                    principal,
                    request.idempotency_key,
                    request_hash(request),
                    request.operation,
                    canonical(request.arguments),
                    request.arguments.get("agent")
                    if request.operation == "agent.execute"
                    else None,
                    request.parent_id,
                    State.CREATED if pending else State.QUEUED,
                    now,
                    now,
                    attempt,
                ),
            )
            self.store.db.execute(
                "INSERT INTO completion_routes(task_id,target) VALUES(?,?)",
                (request.task_id, effective_target),
            )
            for state in (State.CREATED,) if pending else (State.CREATED, State.QUEUED):
                evidence = {"persisted": True}
                if state == State.QUEUED and automatic:
                    evidence["approval_source"] = "principal_policy"
                self.store.db.execute(
                    "INSERT INTO events(task_id,at,state,evidence) VALUES(?,?,?,?)",
                    (request.task_id, now, state, canonical(evidence)),
                )
            if buffered:
                self.input_policy.stage(request, principal)
            self.store.audit(
                "task.requested" if pending else "task.queued",
                principal,
                request.task_id,
                {
                    "operation": request.operation,
                    "request_hash": request_hash(request),
                    "permission_decision": effective,
                },
            )
            if automatic and not held:
                self.store.audit(
                    "task.auto_approved",
                    principal,
                    request.task_id,
                    {
                        "source": "principal_policy",
                        "approval_mode": policy.approval_mode,
                        "operation": request.operation,
                        "request_hash": request_hash(request),
                    },
                )
        self.wake.set()
        return self.store.get(request.task_id, principal)

    def approve(
        self, task_id: str, *, expected_hash: str | None = None, source: str = "local_cli"
    ) -> dict:
        """Local operator authority only; deliberately not an MCP tool."""
        self.input_policy.expire()
        with self.store.transaction():
            task = self.store.get(task_id)
            actual_hash = self.store.db.execute(
                "SELECT request_hash FROM tasks WHERE id=?", (task_id,)
            ).fetchone()[0]
            if expected_hash is not None and expected_hash != actual_hash:
                raise BridgeError("review_conflict", "The reviewed request does not match")
            self.security.principal(task["principal"], task["operation"])
            if task["state"] != State.CREATED:
                raise BridgeError("state_conflict", "Only pending requests can be approved")
            if self.input_policy.waiting(task_id):
                request = TaskRequest(
                    task_id=task_id,
                    idempotency_key=task["idem"],
                    operation=task["operation"],
                    arguments=task["args"],
                    parent_id=task["parent_id"],
                )
                # An explicit click/CLI approval by the trusted local operator is the
                # separate step. Issue and consume its exact-task token atomically.
                token = self.security.grant_in_transaction(task["principal"], request)
                self.input_policy.release(task["principal"], request, token, source=source)
            self._approve_in_transaction(task_id, source)
        self.wake.set()
        return self.store.get(task_id)

    def _approve_in_transaction(self, task_id, source):
        task = self.store.get(task_id)
        self.store.assert_accepting(operation=task["operation"])
        now = time.time()
        self.store.db.execute(
            "UPDATE tasks SET state='queued',updated=? WHERE id=?", (now, task_id)
        )
        self.store.db.execute(
            "INSERT INTO events(task_id,at,state,evidence) VALUES(?,?,?,?)",
            (
                task_id,
                now,
                State.QUEUED,
                canonical({"approval_source": source, "local_operator_approved": True}),
            ),
        )
        self.store.audit(
            "task.approved",
            task["principal"],
            task_id,
            {
                "source": source,
                "operation": task["operation"],
                "request_hash": self.store.db.execute(
                    "SELECT request_hash FROM tasks WHERE id=?", (task_id,)
                ).fetchone()[0],
            },
        )

    async def start(self) -> None:
        if self.workers:
            return
        self.lock.acquire()
        try:
            self.store.recover()
            self.workers = [
                asyncio.create_task(self._worker("normal")) for _ in range(self.config.concurrency)
            ]
            self.workers.extend(
                asyncio.create_task(self._worker("read"))
                for _ in range(self.config.read_concurrency)
            )
            # Read traffic never occupies the independently reserved stop worker.
            self.workers.append(asyncio.create_task(self._worker("stop")))
        except BaseException:
            self.lock.release()
            raise

    async def stop(self) -> None:
        for worker in self.workers:
            worker.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        self.lock.release()

    async def _heartbeat(self, task_id: str) -> None:
        while True:
            await asyncio.sleep(self.config.lease_seconds / 3)
            self.store.db.execute(
                "UPDATE tasks SET lease_until=? WHERE id=? AND lease_owner=? "
                "AND state IN ('accepted','running')",
                (time.time() + self.config.lease_seconds, task_id, self.owner),
            )

    async def _worker(self, lane: str) -> None:
        while True:
            self.wake.clear()
            self.input_policy.expire()
            if self.maintenance:
                self.maintenance()
            task = self.store.claim(self.owner, self.config.lease_seconds, lane)
            if task is None:
                try:
                    await asyncio.wait_for(self.wake.wait(), 2.0)
                except TimeoutError:
                    pass
                continue
            await self._execute(task)

    async def _execute(self, task: dict) -> None:
        heartbeat = asyncio.create_task(self._heartbeat(task["id"]))
        observed_effect = False
        progress_count = 0
        mutating = OPERATIONS[task["operation"]].effect != "read"

        async def running(evidence):
            nonlocal observed_effect
            observed_effect = mutating
            self.store.transition(task["id"], State.RUNNING, evidence, owner=self.owner)

        async def progress(evidence):
            nonlocal observed_effect, progress_count
            observed_effect = mutating
            progress_count += 1
            if progress_count > 256:
                raise UncertainExecution("progress_limit", "Task progress event limit reached")
            with self.store.transaction():
                now = time.time()
                self.store.db.execute(
                    "UPDATE tasks SET evidence=?,updated=? WHERE id=? AND lease_owner=?",
                    (canonical(evidence), now, task["id"], self.owner),
                )
                self.store.db.execute(
                    "INSERT INTO events(task_id,at,state,evidence) VALUES(?,?,?,?)",
                    (task["id"], now, self.store.get(task["id"])["state"], canonical(evidence)),
                )
                self.store.audit(
                    "task.progress",
                    task["principal"],
                    task["id"],
                    {"evidence_hash": digest(evidence)},
                )

        try:
            # Revalidate policy at dispatch time (config or grants may have changed).
            if self.preflight:
                try:
                    self.security.principal(task["principal"], task["operation"])
                    report = self.preflight(task)
                except BridgeError as exc:
                    report = {
                        "ready": False,
                        "operation": task["operation"],
                        "runtime": self.runtime,
                        "checks": [
                            {
                                "kind": "operation",
                                "resource_ref": digest(task["operation"]),
                                "ok": False,
                                "code": exc.code,
                            }
                        ],
                    }
                with self.store.transaction():
                    self.store.audit("task.preflight", task["principal"], task["id"], report)
                if not report["ready"]:
                    code = next(c["code"] for c in report["checks"] if not c["ok"])
                    raise BridgeError(code, "Task prerequisites missing; inspect diagnostic report")
            else:
                self.security.principal(task["principal"], task["operation"])
            result = await self.executor(task, running, progress)
            state = State.COMPLETED if result.get("success", True) else State.FAILED
            self.store.transition(
                task["id"],
                state,
                result.get("evidence", {"operation_returned": True}),
                result=result,
                owner=self.owner,
            )
        except asyncio.CancelledError:
            self.store.transition(
                task["id"],
                State.UNKNOWN,
                {
                    "reason": "dispatcher_shutdown",
                    "side_effect_possible": observed_effect,
                    "last_observation": self.store.get(task["id"])["evidence"],
                },
                owner=self.owner,
            )
            raise
        except Exception as exc:
            state = (
                State.UNKNOWN
                if observed_effect or isinstance(exc, UncertainExecution)
                else State.FAILED
            )
            # Exception text from subprocesses, HTTP and validation may include secrets.
            code = exc.code if isinstance(exc, BridgeError) else "execution_error"
            self.store.transition(
                task["id"],
                state,
                {
                    "exception_type": type(exc).__name__,
                    "provider_error": getattr(exc, "provider_error", None),
                    "safe_to_retry": state == State.FAILED and not observed_effect,
                    "last_observation": self.store.get(task["id"])["evidence"],
                },
                error={"code": code},
                owner=self.owner,
            )
        finally:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)

    def cancel_queued(self, principal: str, task_id: str) -> dict:
        self.security.principal(principal, "task.cancel")
        task = self.store.get(task_id, principal)
        if task["state"] not in {State.CREATED, State.QUEUED}:
            raise BridgeError(
                "state_conflict", "Only pending or queued tasks can be cancelled here"
            )
        self.store.transition(
            task_id,
            State.CANCELLED,
            {"cancelled_by_owner": True},
            expected_states={State.CREATED, State.QUEUED},
        )
        return self.store.get(task_id, principal)

    def reconcile(self, task_id: str, state: State, reference: str) -> dict:
        if state not in {State.COMPLETED, State.FAILED, State.CANCELLED} or not reference.strip():
            raise BridgeError(
                "reconciliation", "A terminal state and evidence reference are required"
            )
        if self.store.get(task_id)["state"] != State.UNKNOWN:
            raise BridgeError("state_conflict", "Only unknown tasks require reconciliation")
        self.store.transition(
            task_id, state, {"source": "local_operator_attestation", "reference": reference}
        )
        return self.store.get(task_id)

    def retry(self, principal: str, original_id: str, request: TaskRequest, approval: str) -> dict:
        original = self.store.get(original_id, principal)
        if original["state"] != State.FAILED or not original["evidence"].get("safe_to_retry"):
            raise BridgeError("unsafe_retry", "Retry requires proof that execution never started")
        if original["attempt"] >= 3:
            raise BridgeError("retry_limit", "At most three attempts are allowed")
        if (
            request.operation != original["operation"]
            or request.arguments != original["args"]
            or request.parent_id != original_id
        ):
            raise BridgeError(
                "retry_conflict", "Retry must preserve operation/arguments and link its parent"
            )
        return self.enqueue(principal, request, approval, attempt=original["attempt"] + 1)

    async def wait(self, principal: str, task_id: str, timeout: float = 30) -> dict:
        async with asyncio.timeout(timeout):
            while True:
                task = self.store.get(task_id, principal)
                if task["state"] not in {
                    State.CREATED,
                    State.QUEUED,
                    State.ACCEPTED,
                    State.RUNNING,
                }:
                    return task
                await asyncio.sleep(0.05)
