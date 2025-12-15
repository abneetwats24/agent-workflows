"""
Factory for creating configured MCP clients.
"""
import httpx
import base64
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

class DirectAuthClientProvider(OAuthClientProvider):
    """Custom provider for Resource Owner Password Credentials Grant."""
    def __init__(self, username: str | None = None, password: str | None = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.username = username
        self.password = password

    async def _perform_authorization(self) -> httpx.Request:
        # Check if we should do password grant
        grant_types = self.context.client_metadata.grant_types
        if self.username and self.password and "password" in grant_types:
             print("🔓 Performing password grant flow (Headless)...")
             
             token_endpoint = None
             if self.context.oauth_metadata:
                 token_endpoint = str(self.context.oauth_metadata.token_endpoint)
                 
             if not token_endpoint:
                 raise ValueError("Token endpoint not found for password grant flow")
             
             data = {
                 "grant_type": "password",
                 "username": self.username,
                 "password": self.password,
                 "scope": self.context.client_metadata.scope or "mcp:tools"
             }
             
             auth_method = self.context.client_metadata.token_endpoint_auth_method
             headers = {
                 "Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"
             }
             
             # Handle client auth
             if auth_method == "client_secret_basic":
                 auth_str = f"{self.context.client_info.client_id}:{self.context.client_info.client_secret}"
                 b64_auth = base64.b64encode(auth_str.encode()).decode()
                 headers["Authorization"] = f"Basic {b64_auth}"
             elif auth_method == "client_secret_post":
                 data["client_id"] = self.context.client_info.client_id
                 data["client_secret"] = self.context.client_info.client_secret
                 
             request = httpx.Request("POST", token_endpoint, data=data, headers=headers)
             return request
             
        return await super()._perform_authorization()

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
    callback_handler: Any | None = None,
    username: str | None = None,
    password: str | None = None
) -> OAuthClientProvider:
    """
    Create and configure an OAuthClientProvider.
    """
    
    if grant_types is None:
        grant_types = ["client_credentials"]
        
    # Auto-add password grant if credentials provided
    if username and password and "password" not in grant_types:
        grant_types.append("password")

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
    
    # Use custom provider if credentials present
    provider_class = DirectAuthClientProvider if (username and password) else OAuthClientProvider
    kwargs = {}
    if username and password:
        kwargs["username"] = username
        kwargs["password"] = password

    return provider_class(
        server_url=server_url,
        client_metadata=OAuthClientMetadata.model_validate(client_metadata_dict),
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
        **kwargs
    )
