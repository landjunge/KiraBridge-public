"""Grok mobile/web MCP access, distinct from the managed Grok CLI worker."""

from pathlib import Path

from kirabridge.bridge_core.config import Config


def state_dir(config: Config) -> Path:
    return config.state_path / "grok-app-connector"


def effective_settings(config: Config):
    """Use only an owner-private supervisor profile for its current tunnel origin."""
    from kirabridge.bridge_core.config import GrokConnectorConfig
    from kirabridge.local_runtime import private_json

    settings = config.grok_connector
    profile = state_dir(config) / "runtime-profile.json"
    if not settings.enabled or not profile.exists():
        return settings
    data = private_json(profile)
    if data.get("owner") != "kirabridge-grok-app" or data.get("port") != settings.port:
        from kirabridge.bridge_core.models import BridgeError

        raise BridgeError("connector_profile_conflict", "Inspect the local connector profile")
    return GrokConnectorConfig.model_validate(
        {**settings.model_dump(), "public_origin": data["public_origin"]}
    )
