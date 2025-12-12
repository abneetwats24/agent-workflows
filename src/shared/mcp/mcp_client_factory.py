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
    skip_registration: bool = True,
    grant_types: list[str] | None = None,
    token_endpoint_auth_method: str = "client_secret_post",
    redirect_handler: Any | None = None,
    callback_handler: Any | None = None
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
        grant_types: List of grant types to support.
        token_endpoint_auth_method: Auth method for token endpoint.
        redirect_handler: Handler for interactive redirects.
        callback_handler: Handler for interactive callbacks (code entry).
    """
    
    if grant_types is None:
        grant_types = ["client_credentials"]

    client_metadata_dict = {
        "client_id": client_id,
        "client_secret": client_secret,
        "token_endpoint_auth_method": token_endpoint_auth_method,
        "grant_types": grant_types,
        "scope": scope,
        "redirect_uris": redirect_uris,
    }
    
    storage = InMemoryTokenStorage()
    
    if skip_registration:
        # Pre-populate client info to skip dynamic registration
        client_info = OAuthClientInformationFull(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uris=[redirect_uris[0]] if redirect_uris else [],
            token_endpoint_auth_method=token_endpoint_auth_method,
            grant_types=grant_types,
            scope=scope
        )
        await storage.set_client_info(client_info)
    
    return OAuthClientProvider(
        server_url=server_url,
        client_metadata=OAuthClientMetadata.model_validate(client_metadata_dict),
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler
    )
