"""OAuth-protected, fixed-identity MCP gateway for an external Grok application.

The SDK supplies OAuth handlers and bearer authentication. This application
owns one HTTP-client lifespan and proxies only the exact MCP route to the
configured private loopback daemon. It never forwards external bearer tokens.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import ssl
import time
from contextlib import asynccontextmanager
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

import httpx
from mcp.server.auth.handlers.metadata import MetadataHandler, ProtectedResourceMetadataHandler
from mcp.server.auth.handlers.register import RegistrationErrorResponse, RegistrationHandler
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.auth.provider import RegistrationError
from mcp.server.auth.routes import (
    build_metadata,
    build_resource_metadata_url,
    create_auth_routes,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthMetadata,
    ProtectedResourceMetadata,
)
from pydantic import AnyHttpUrl, ValidationError, field_serializer
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route, request_response

from kirabridge import __version__
from kirabridge.bridge_core.config import Config
from kirabridge.bridge_core.models import BridgeError
from kirabridge.grok_connector import effective_settings
from kirabridge.grok_connector.auth_store import OAuthStore
from kirabridge.grok_connector.provider import GrokOAuthProvider
from kirabridge.local_runtime import peer

_OPAQUE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,79}$")


class _AuthorizationMetadata(OAuthMetadata):
    authorization_response_iss_parameter_supported: bool = True

    @field_serializer("issuer")
    def canonical_issuer(self, value):
        return str(value).rstrip("/")


class _ResourceMetadata(ProtectedResourceMetadata):
    @field_serializer("authorization_servers")
    def canonical_servers(self, value):
        return [str(item).rstrip("/") for item in value]


class _RegistrationHandler(RegistrationHandler):
    """SDK 1.30 compatibility for an authorization-code-only client.

    The SDK hardcodes refresh-token support as a registration requirement, even
    for clients that did not request it. There is no validation hook to override.
    All other registrations stay on the original SDK handler; this narrow branch
    retains the same SDK models, scope checks, generated secrets and provider.
    Omitted grant_types use RFC 7591's authorization_code-only default, rather
    than the SDK's refresh-capable default. Submitted grants are never widened.
    """

    async def handle(self, request):
        try:
            body = await request.json()
            if isinstance(body, dict) and "grant_types" not in body:
                body = {**body, "grant_types": ["authorization_code"]}
            metadata = OAuthClientMetadata.model_validate(body)
        except ValidationError:
            return await super().handle(request)
        if metadata.grant_types != ["authorization_code"]:
            return await super().handle(request)

        def error(description):
            return PydanticJSONResponse(
                content=RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description=description,
                ),
                status_code=400,
            )

        if metadata.token_endpoint_auth_method is None:
            metadata.token_endpoint_auth_method = "client_secret_post"
        if metadata.scope is None and self.options.default_scopes is not None:
            metadata.scope = " ".join(self.options.default_scopes)
        elif metadata.scope is not None and self.options.valid_scopes is not None:
            if not set(metadata.scope.split()).issubset(self.options.valid_scopes):
                return error("Requested scopes are not valid")
        if "code" not in metadata.response_types:
            return error("response_types must include 'code' for authorization_code grant")
        issued = int(time.time())
        client = OAuthClientInformationFull(
            **metadata.model_dump(),
            client_id=str(uuid4()),
            client_id_issued_at=issued,
            client_secret=None
            if metadata.token_endpoint_auth_method == "none"
            else secrets.token_hex(32),
            client_secret_expires_at=issued + self.options.client_secret_expiry_seconds
            if self.options.client_secret_expiry_seconds is not None
            else None,
        )
        try:
            await self.provider.register_client(client)
        except RegistrationError as exc:
            return PydanticJSONResponse(
                content=RegistrationErrorResponse(
                    error=exc.error,
                    error_description=exc.error_description,
                ),
                status_code=400,
            )
        return PydanticJSONResponse(content=client, status_code=201)


def _error(code, status):
    return JSONResponse({"error": code}, status_code=status)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Repeated JSON field")
        value[key] = item
    return value


class _ExactTokenVerifier:
    def __init__(self, provider, issuer, principal):
        self.provider, self.issuer, self.principal = provider, issuer, principal

    async def verify_token(self, token):
        value = await self.provider.load_access_token(token)
        if (
            value is None
            or value.resource != self.issuer + "/mcp"
            or value.subject != self.principal
            or (value.claims or {}).get("iss") != self.issuer
            or value.scopes != ["kirabridge"]
        ):
            return None
        return value


class _GatewayBoundary:
    """Bound every route before SDK parsing and replace SDK wildcard CORS."""

    def __init__(self, app, *, settings, issuer, ready):
        self.app, self.settings, self.issuer, self.ready = app, settings, issuer, ready
        self.active = 0
        self.hosts = {
            urlsplit(issuer).netloc.lower(),
            f"127.0.0.1:{settings.port}",
            f"localhost:{settings.port}",
            f"[::1]:{settings.port}",
        }
        self.origins = {issuer, *("https://" + host for host in settings.redirect_hosts)}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        raw = scope.get("headers", [])
        if sum(len(key) + len(value) for key, value in raw) > 16384:
            return await _error("header_limit", 431)(scope, receive, send)
        sensitive = {
            b"host",
            b"origin",
            b"authorization",
            b"content-type",
            b"content-length",
            b"mcp-protocol-version",
            b"mcp-session-id",
        }
        for key in sensitive:
            if sum(name.lower() == key for name, _ in raw) > 1:
                return await _error("ambiguous_headers", 400)(scope, receive, send)
        headers = {key.lower(): value for key, value in raw}
        host = headers.get(b"host", b"").decode("latin-1").lower()
        origin = headers.get(b"origin", b"").decode("latin-1")
        if host not in self.hosts:
            return await _error("invalid_host", 403)(scope, receive, send)
        if origin and origin not in self.origins:
            return await _error("invalid_origin", 403)(scope, receive, send)
        if self.active >= self.settings.max_requests:
            return await _error("request_limit", 429)(scope, receive, send)

        async def secure_send(message):
            if message["type"] == "http.response.start":
                cleaned = [
                    (key, value)
                    for key, value in message.get("headers", [])
                    if not key.lower().startswith(b"access-control-")
                    and key.lower() not in {b"cache-control", b"pragma"}
                ]
                cleaned += [
                    (b"cache-control", b"no-store"),
                    (b"pragma", b"no-cache"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-content-type-options", b"nosniff"),
                    (
                        b"content-security-policy",
                        b"default-src 'none'; script-src 'self'; "
                        b"connect-src 'self'; base-uri 'none'; form-action 'none'; "
                        b"frame-ancestors 'none'",
                    ),
                ]
                if origin:
                    cleaned += [
                        (b"access-control-allow-origin", origin.encode("latin-1")),
                        (
                            b"access-control-expose-headers",
                            b"WWW-Authenticate, MCP-Protocol-Version",
                        ),
                        (b"vary", b"Origin"),
                    ]
                    if scope["method"] == "OPTIONS":
                        cleaned += [
                            (b"access-control-allow-methods", b"GET, POST, DELETE, OPTIONS"),
                            (
                                b"access-control-allow-headers",
                                b"Authorization, Content-Type, MCP-Protocol-Version",
                            ),
                        ]
                message["headers"] = cleaned
            await send(message)

        if scope["method"] == "OPTIONS":
            if not origin or scope["path"] not in {
                "/mcp",
                "/register",
                "/token",
                "/revoke",
                "/.well-known/oauth-authorization-server",
                "/.well-known/oauth-protected-resource/mcp",
            }:
                return await _error("invalid_preflight", 403)(scope, receive, secure_send)
            return await Response(status_code=204)(scope, receive, secure_send)
        if not self.ready() and scope["path"] != "/health":
            return await _error("gateway_not_ready", 503)(scope, receive, secure_send)
        self.active += 1
        try:
            request = Request(scope, receive)
            body = bytearray()
            try:
                async with asyncio.timeout(10):
                    async for chunk in request.stream():
                        if len(body) + len(chunk) > self.settings.max_body_bytes:
                            return await _error("payload_limit", 413)(scope, receive, secure_send)
                        body.extend(chunk)
            except TimeoutError:
                return await _error("request_timeout", 408)(scope, receive, secure_send)
            if len(scope.get("query_string", b"")) > 8192:
                return await _error("query_limit", 400)(scope, receive, secure_send)
            path = scope["path"]
            if path == "/register" and scope["method"] == "POST":
                if headers.get(b"content-type", b"").split(b";")[0] != b"application/json":
                    return await _error("invalid_client_metadata", 400)(scope, receive, secure_send)
                try:
                    value = json.loads(body, object_pairs_hook=_unique_object)
                    if not isinstance(value, dict):
                        raise ValueError
                except (ValueError, UnicodeDecodeError, RecursionError):
                    return await _error("invalid_client_metadata", 400)(scope, receive, secure_send)
            if path == "/mcp" and (
                scope.get("query_string")
                or headers.get(b"mcp-session-id")
                or headers.get(b"last-event-id")
            ):
                return await _error("stateless_mcp_required", 400)(scope, receive, secure_send)
            if path in {"/token", "/revoke", "/authorize"}:
                encoded = scope.get("query_string", b"") if scope["method"] == "GET" else body
                if scope["method"] != "GET" and headers.get(b"content-type", b"").split(b";")[
                    0
                ] != (b"application/x-www-form-urlencoded"):
                    return await _error("invalid_request", 400)(scope, receive, secure_send)
                try:
                    text = bytes(encoded).decode("utf-8")
                    if re.search(r"%(?![0-9A-Fa-f]{2})", text):
                        raise ValueError
                    pairs = parse_qsl(
                        text, keep_blank_values=True, strict_parsing=True, max_num_fields=32
                    )
                    if len(dict(pairs)) != len(pairs):
                        raise ValueError
                except (ValueError, UnicodeDecodeError):
                    return await _error("invalid_request", 400)(scope, receive, secure_send)
                if path == "/token" and dict(pairs).get("resource") != self.issuer + "/mcp":
                    return await _error("invalid_target", 400)(scope, receive, secure_send)
                if path == "/token" and dict(pairs).get("grant_type") == "authorization_code":
                    if not re.fullmatch(
                        r"[A-Za-z0-9._~-]{43,128}", dict(pairs).get("code_verifier", "")
                    ):
                        return await _error("invalid_request", 400)(scope, receive, secure_send)
            sent = False

            async def replay_body():
                nonlocal sent
                if not sent:
                    sent = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, replay_body, secure_send)
        finally:
            self.active -= 1


def create_gateway(config: Config, *, transport: httpx.AsyncBaseTransport | None = None):
    settings = effective_settings(config)
    if not settings.enabled or not settings.public_origin:
        raise BridgeError("connector_disabled", "Configure the external Grok connector first")
    issuer = settings.public_origin.rstrip("/")
    target = peer(config, settings.principal)
    store = OAuthStore(
        config.state_path / "grok-app-connector" / "oauth.sqlite3",
        issuer=issuer,
        principal=settings.principal,
        redirect_hosts=settings.redirect_hosts,
    )
    provider = GrokOAuthProvider(store)

    @asynccontextmanager
    async def lifespan(app):
        verify = ssl.create_default_context(cafile=target.ca_file) if target.ca_file else True
        async with httpx.AsyncClient(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(30, connect=5),
            verify=verify,
        ) as client:
            app.state.http_client = client
            app.state.started = True
            try:
                yield
            finally:
                app.state.started = False
                app.state.http_client = None
                store.close()

    async def health(request):
        return JSONResponse(
            {
                "name": "KiraBridge Grok connector",
                "version": __version__,
                "healthy": bool(app.state.started),
            }
        )

    async def consent(request):
        request_id = request.path_params["request_id"]
        if not _OPAQUE.fullmatch(request_id):
            return _error("not_found", 404)
        # The page contains only an opaque, short-lived request identifier.
        # Callback codes/state remain out of HTML, attributes, and referrers.
        return HTMLResponse(
            '<!doctype html><html lang="de"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            "<title>KiraBridge verbinden</title><body><h1>KiraBridge verbinden</h1>"
            "<p>Bestätige die Verbindung einmalig in KiraBridge auf deinem Mac. "
            "Diese Seite wartet auf deine lokale Entscheidung.</p>"
            '<p>Verbindungskennung: <strong id="connection-code">'
            f"{request_id[-12:].upper()}</strong></p>"
            "<p>Vergleiche diese Kennung mit der Anmeldung auf deinem Mac.</p>"
            f'<p id="status" data-request="{request_id}">Freigabe ausstehend.</p>'
            '<p><a href="http://127.0.0.1:8766/grok-connector" rel="noreferrer">'
            "Am Mac: lokale Verbindungsfreigabe öffnen</a></p>"
            '<script src="/oauth/consent.js" defer></script></body></html>'
        )

    async def consent_script(request):
        return Response(_CONSENT_SCRIPT, media_type="application/javascript")

    async def poll(request):
        request_id = request.path_params["request_id"]
        if not _OPAQUE.fullmatch(request_id):
            return _error("not_found", 404)
        try:
            return JSONResponse(store.poll(request_id))
        except BridgeError:
            return _error("not_found", 404)

    async def proxy(request):
        if request.method == "POST" and request.headers.get("content-type", "").split(";")[0] != (
            "application/json"
        ):
            return _error("invalid_content_type", 415)
        body = await request.body()
        headers = {
            "Authorization": "Bearer " + target.token,
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        protocol = request.headers.get("mcp-protocol-version")
        if protocol:
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", protocol):
                return _error("invalid_mcp_version", 400)
            headers["MCP-Protocol-Version"] = protocol
        try:
            async with (
                asyncio.timeout(35),
                request.app.state.http_client.stream(
                    request.method,
                    target.url,
                    headers=headers,
                    content=body,
                ) as response,
            ):
                if response.is_redirect:
                    return _error("upstream_redirect_denied", 502)
                if response.status_code in {401, 403}:
                    return _error("upstream_authentication_failed", 502)
                if response.headers.get("content-type", "").split(";")[0] == "text/event-stream":
                    return _error("upstream_stateless_json_required", 502)
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(content) + len(chunk) > settings.max_body_bytes:
                        return _error("upstream_response_limit", 502)
                    content.extend(chunk)
                output = Response(
                    bytes(content),
                    status_code=response.status_code,
                    media_type=None,
                    headers={
                        "Content-Type": response.headers.get("content-type", "application/json")
                    },
                )
                if response.status_code == 200:
                    _record_call(store, request.user.access_token.client_id, body, bytes(content))
                return output
        except (httpx.TimeoutException, TimeoutError):
            return _error("upstream_outcome_unknown", 504)
        except httpx.HTTPError:
            return _error("upstream_outcome_unknown", 502)

    protected = AuthenticationMiddleware(
        RequireAuthMiddleware(
            request_response(proxy),
            required_scopes=["kirabridge"],
            resource_metadata_url=build_resource_metadata_url(AnyHttpUrl(issuer + "/mcp")),
        ),
        backend=BearerAuthBackend(
            _ExactTokenVerifier(provider, issuer, settings.principal),
            resource_server_url=AnyHttpUrl(issuer + "/mcp"),
        ),
    )
    routes = create_auth_routes(
        provider,
        AnyHttpUrl(issuer),
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["kirabridge"],
            default_scopes=["kirabridge"],
        ),
        revocation_options=RevocationOptions(enabled=True),
    )
    # SDK 1.30 accepts public clients, but omits "none" in default discovery.
    # Keep its metadata/handler and explicitly advertise that supported method.
    metadata = build_metadata(
        AnyHttpUrl(issuer),
        None,
        ClientRegistrationOptions(
            enabled=True, valid_scopes=["kirabridge"], default_scopes=["kirabridge"]
        ),
        RevocationOptions(enabled=True),
    )
    metadata = _AuthorizationMetadata.model_validate(metadata.model_dump())
    metadata.token_endpoint_auth_methods_supported = [
        "none",
        "client_secret_post",
        "client_secret_basic",
    ]
    routes = [
        route
        for route in routes
        if route.path
        not in {
            "/.well-known/oauth-authorization-server",
            "/register",
        }
    ]
    routes.append(
        Route(
            "/register",
            _RegistrationHandler(
                provider,
                ClientRegistrationOptions(
                    enabled=True, valid_scopes=["kirabridge"], default_scopes=["kirabridge"]
                ),
            ).handle,
            methods=["POST"],
        )
    )
    routes.append(
        Route(
            "/.well-known/oauth-authorization-server",
            MetadataHandler(metadata).handle,
            methods=["GET"],
        )
    )
    resource_metadata = _ResourceMetadata(
        resource=AnyHttpUrl(issuer + "/mcp"),
        authorization_servers=[AnyHttpUrl(issuer)],
        scopes_supported=["kirabridge"],
        resource_name="KiraBridge Grok app connector",
    )
    routes.append(
        Route(
            "/.well-known/oauth-protected-resource/mcp",
            ProtectedResourceMetadataHandler(resource_metadata).handle,
            methods=["GET"],
        )
    )
    routes += [
        Route("/health", health),
        Route("/oauth/consent.js", consent_script),
        Route("/oauth/consent/{request_id}", consent),
        Route("/oauth/poll/{request_id}", poll),
        Route("/mcp", protected, methods=["GET", "POST", "DELETE"]),
    ]
    app = Starlette(routes=routes, lifespan=lifespan)
    app.router.redirect_slashes = False
    app.state.oauth_store = store
    app.state.started = False
    app.state.http_client = None
    app.add_middleware(
        _GatewayBoundary,
        settings=settings,
        issuer=issuer,
        ready=lambda: app.state.started,
    )
    return app


def _record_call(store, client_id, request_body, response_body):
    try:
        incoming, outgoing = json.loads(request_body), json.loads(response_body)
        if not isinstance(incoming, dict) or incoming.get("method") != "tools/call":
            return
        tool = incoming.get("params", {}).get("name")
        result = outgoing.get("result", {})
        if (
            not isinstance(tool, str)
            or not _TOOL.fullmatch(tool)
            or outgoing.get("error")
            or not isinstance(result, dict)
            or result.get("isError")
            or (
                isinstance(result.get("structuredContent"), dict)
                and result["structuredContent"].get("error")
            )
        ):
            return
        store.record_use(client_id, tool=tool, request_ref=hashlib.sha256(request_body).hexdigest())
    except (ValueError, TypeError, AttributeError):
        pass


_CONSENT_SCRIPT = r""""use strict";
const statusNode = document.getElementById("status");
const requestId = statusNode.dataset.request;
let attempts = 0;
async function poll() {
  if (++attempts > 300) {
    statusNode.textContent = "Die Wartezeit ist abgelaufen. Starte die Verbindung erneut.";
    return;
  }
  try {
    const response = await fetch("/oauth/poll/" + encodeURIComponent(requestId),
      {cache: "no-store", credentials: "omit", redirect: "error"});
    const data = await response.json();
    if (response.ok && data.status === "approved" && typeof data.redirect_url === "string") {
      const destination = new URL(data.redirect_url);
      if (destination.protocol !== "https:" || destination.username ||
          destination.password || destination.hash) {
        throw new Error("Unsafe callback");
      }
      statusNode.textContent = "Verbindung freigegeben. Zurück zur Anwendung …";
      location.replace(destination.href);
      return;
    }
    if (!response.ok || ["denied", "expired"].includes(data.status)) {
      statusNode.textContent = "Die Verbindung wurde abgelehnt oder ist abgelaufen.";
      return;
    }
  } catch (_) {
    statusNode.textContent = "Verbindung nicht bestätigt. Warte auf lokale Freigabe …";
  }
  setTimeout(poll, 2000);
}
poll();
"""
