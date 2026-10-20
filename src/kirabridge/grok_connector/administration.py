"""Local connector administration; owns OAuth storage access for both UI routes."""

from contextlib import contextmanager

from kirabridge.bridge_core.models import BridgeError
from kirabridge.grok_connector import effective_settings, state_dir
from kirabridge.grok_connector.auth_store import OAuthStore


class ConnectorAdministration:
    def __init__(self, config):
        self.config = config

    def settings(self):
        return effective_settings(self.config())

    @contextmanager
    def store(self, settings):
        store = OAuthStore(
            state_dir(self.config()) / "oauth.sqlite3",
            issuer=settings.public_origin,
            principal=settings.principal,
            redirect_hosts=settings.redirect_hosts,
        )
        try:
            yield store
        finally:
            store.close()

    def summary(self):
        settings = self.settings()
        result = {
            "url": settings.public_origin + "/mcp" if settings.public_origin else None,
            "pending": [],
            "last_use": None,
        }
        if settings.enabled:
            with self.store(settings) as store:
                result["pending"] = store.list_pending()
                result["last_use"] = store.status().get("last_use")
        return result

    def status(self):
        settings = self.settings()
        policy = self.config().principals.get(settings.principal)
        result = {
            "enabled": settings.enabled,
            "principal": settings.principal,
            "cli_principal": "grok",
            "public_origin": settings.public_origin,
            "connector_url": settings.public_origin + "/mcp" if settings.public_origin else None,
            "gateway_reachability": "unverified",
            "mobile_app_call": "unverified",
            "eve_voice_tools": "unverified",
            "principal_configured": policy is not None,
            "task_approval_mode": policy.approval_mode if policy else "unknown",
            "capabilities": policy.capabilities if policy else [],
            "pending": [],
            "authorization": None,
        }
        if settings.enabled:
            if not settings.public_origin:
                raise BridgeError("connector_not_configured", "A public HTTPS origin is required")
            with self.store(settings) as store:
                result["authorization"] = store.status()
                fields = (
                    "id",
                    "client_name",
                    "redirect_uri",
                    "scopes",
                    "created",
                    "expires_at",
                    "principal",
                )
                result["pending"] = [
                    {key: item.get(key) for key in fields} for item in store.list_pending()
                ]
        return result

    def decide(self, request_id, allow):
        settings = self.settings()
        if not settings.enabled or not settings.public_origin:
            raise BridgeError("connector_disabled", "The Grok app connector is not enabled")
        with self.store(settings) as store:
            result = store.decide(request_id, allow)
        if result.get("status") not in {"pending", "approved", "denied", "expired"}:
            raise BridgeError("connector_state_unknown", "Authorization outcome is unknown")
        return result
