"""Authenticated HTTP presentation for the local operator application."""

from __future__ import annotations

import json
from pathlib import Path

from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from kirabridge.bridge_core.models import BridgeError
from kirabridge.operations_service import configure_access as configure_access
from kirabridge.operations_service import replace_section as replace_section

ASSETS = Path(__file__).with_name("console_assets")


class ControlCenter:
    def __init__(self, service, authenticate):
        self.service, self.authenticate = service, authenticate
        self.seen_surfaces = set()
        self.routes = [
            Route("/protocol", self.protocol_page),
            Route("/api/control/status", self.status),
            Route("/api/control/action", self.action, methods=["POST"]),
            Route("/api/control/doctor", self.doctor, methods=["GET", "POST"]),
            Route("/api/control/permissions", self.permissions, methods=["POST"]),
            Route("/api/control/protocol", self.protocol),
            Route("/api/control/connections", self.connections),
            Route("/api/control/terminals", self.terminals),
            Route("/api/control/terminal/read", self.terminal_read, methods=["POST"]),
            Route("/api/control/terminal/input", self.terminal_input, methods=["POST"]),
            Route("/api/control/consent/{request_id}", self.consent, methods=["POST"]),
        ]

    async def status(self, request):
        self.authenticate(request)
        surface = (
            "desktop" if "KiraBridgeDesktop" in request.headers.get("user-agent", "") else "browser"
        )
        if surface not in self.seen_surfaces:
            self.seen_surfaces.add(surface)
            self.service.record_surface(surface)
        return JSONResponse(await self.service.snapshot())

    async def terminals(self, request):
        self.authenticate(request)
        return JSONResponse(await self.service.rpc("session_catalog"))

    async def terminal_read(self, request):
        self.authenticate(request)
        value = await self.body(request)
        if not isinstance(value.get("pane_id"), str) or type(value.get("expected_pid")) is not int:
            raise BridgeError("invalid_request", "Bitte eine aktuelle Sitzung wählen")
        return JSONResponse(
            await self.service.rpc(
                "session_read",
                {
                    "pane_id": value["pane_id"],
                    "expected_pid": value["expected_pid"],
                },
            )
        )

    async def body(self, request):
        from kirabridge.approval_console import limited_body

        try:
            value = json.loads(await limited_body(request))
        except (ValueError, UnicodeDecodeError):
            raise BridgeError("invalid_request", "Die Eingabe ist ungültig") from None
        if not isinstance(value, dict):
            raise BridgeError("invalid_request", "Die Eingabe ist ungültig")
        return value

    async def protocol_page(self, request):
        return HTMLResponse((ASSETS / "protocol.html").read_text())

    async def protocol(self, request):
        self.authenticate(request)
        try:
            after = max(0, int(request.query_params.get("after", "0")))
            before = max(0, int(request.query_params.get("before", "0")))
        except ValueError:
            raise BridgeError("invalid_request", "Ungültige Protokollposition") from None
        return JSONResponse(self.service.queries.protocol(after, before))

    async def terminal_input(self, request):
        self.authenticate(request)
        return JSONResponse(await self.service.terminal_input(await self.body(request)))

    async def action(self, request):
        self.authenticate(request)
        return JSONResponse(await self.service.action(await self.body(request)))

    async def permissions(self, request):
        self.authenticate(request)
        return JSONResponse(await self.service.permissions(await self.body(request)))

    async def doctor(self, request):
        self.authenticate(request)
        return JSONResponse(await self.service.doctor(repair=request.method == "POST"))

    async def connections(self, request):
        self.authenticate(request)
        return JSONResponse(self.service.connections())

    async def consent(self, request):
        self.authenticate(request)
        value = await self.body(request)
        if type(value.get("allow")) is not bool:
            raise BridgeError("invalid_request", "Eine Entscheidung fehlt")
        return JSONResponse(
            self.service.connectors.decide(request.path_params["request_id"], value["allow"])
        )
