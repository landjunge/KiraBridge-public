"""MCP SDK OAuth provider, with persistent single-use grants and rotated token families."""

from __future__ import annotations

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from kirabridge.grok_connector.auth_store import OAuthStore


class GrokOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    def __init__(self, store: OAuthStore):
        self.store = store

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.store.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.store.register_client(client_info)

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        request_id = self.store.request_authorization(client, params)
        return self.store.issuer + "/oauth/consent/" + request_id

    async def load_authorization_code(
        self, client, authorization_code: str
    ) -> AuthorizationCode | None:
        return self.store.load_code(client, authorization_code)

    async def exchange_authorization_code(self, client, authorization_code) -> OAuthToken:
        # The SDK token handler validates the S256 verifier and exact redirect
        # before this call. The store atomically consumes the original grant.
        return self.store.exchange_code(client, authorization_code)

    async def load_refresh_token(self, client, refresh_token: str) -> RefreshToken | None:
        return self.store.load_refresh(client, refresh_token)

    async def exchange_refresh_token(self, client, refresh_token, scopes: list[str]) -> OAuthToken:
        return self.store.exchange_refresh(client, refresh_token, scopes)

    async def load_access_token(self, token: str) -> AccessToken | None:
        return self.store.load_access(token)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self.store.revoke_token(token)
