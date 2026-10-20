from __future__ import annotations

from kirabridge.bridge_core.bridge import Bridge
from kirabridge.bridge_core.models import BridgeError
from kirabridge.mcp_gateway.server import create_server


class AuthenticatedHTTP:
    """Authenticate every request, cap concurrent requests, forbid oversized request bodies."""

    def __init__(self, app, bridge: Bridge):
        self.app, self.bridge = app, bridge
        self.active = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        try:
            header = headers.get(b"authorization", b"").decode("ascii")
            if not header.startswith("Bearer "):
                raise BridgeError("unauthorized", "Authentication required")
            self.bridge.security.authenticate(header[7:])
        except (BridgeError, UnicodeDecodeError):
            await self.respond(send, 401, b"Authentication required")
            return
        if self.active >= self.bridge.config.max_http_requests:
            await self.respond(send, 429, b"Too many concurrent requests")
            return
        self.active += 1
        try:
            await self.app(scope, receive, send)
        finally:
            self.active -= 1

    @staticmethod
    async def respond(send, status, body):
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", b"Bearer")],
            }
        )
        await send({"type": "http.response.body", "body": body})


def create_http_app(bridge: Bridge):
    bridge.config.validate_network()
    server = create_server(bridge, transport="http")
    return AuthenticatedHTTP(server.streamable_http_app(), bridge)
