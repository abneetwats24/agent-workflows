"""
Factory for creating configured MCP clients.
"""
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from typing import Any

class InMemoryTokenStorage(TokenStorage):
    """Simple in-memory token storage implementation."""

    def __init__(self):
        self._tokens: OAuthToken | None = None
        self._client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_info = client_info

async def create_mcp_oauth_provider(
    server_url: str,
    client_id: str,
    client_secret: str,
    redirect_uris: list[str],
    scope: str = "mcp:tools",
    skip_registration: bool = True
) -> OAuthClientProvider:
    """
    Create and configure an OAuthClientProvider.
    
    Args:
        server_url: The URL of the MCP server.
        client_id: Keycloak client ID.
        client_secret: Keycloak client secret.
        redirect_uris: List of valid redirect URIs for the client.
        scope: OAuth scope to request.
        skip_registration: Whether to pre-populate client info to skip dynamic registration.
    """
    
    client_metadata_dict = {
        "client_id": client_id,
        "client_secret": client_secret,
        "token_endpoint_auth_method": "client_secret_post",
        "grant_types": ["client_credentials"],
        "scope": scope,
        "redirect_uris": redirect_uris,
    }
    
    storage = InMemoryTokenStorage()
    
    if skip_registration:
        # Pre-populate client info to skip dynamic registration
        client_info = OAuthClientInformationFull(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uris=[redirect_uris[0]],
            token_endpoint_auth_method="client_secret_post",
            grant_types=["client_credentials"],
            scope=scope
        )
        await storage.set_client_info(client_info)
    
    return OAuthClientProvider(
        server_url=server_url,
        client_metadata=OAuthClientMetadata.model_validate(client_metadata_dict),
        storage=storage,
        redirect_handler=None,
        callback_handler=None
    )
