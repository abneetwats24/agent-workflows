"""
Configuration for MCP clients.
"""
import os
from dataclasses import dataclass, field
from typing import Callable, Awaitable
from dotenv import load_dotenv

load_dotenv()

@dataclass
class KeycloakConfig:
    url: str
    client_id: str
    client_secret: str
    realm: str

    @classmethod
    def from_env(cls) -> "KeycloakConfig":
        return cls(
            url=os.getenv("KEYCLOAK_URL", "http://192.168.10.7:5555"),
            client_id=os.getenv("KEYCLOAK_CLIENT_ID", "abneet_mcp_client"),
            client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET", "REMOVED"),
            realm=os.getenv("KEYCLOAK_REALM", "openspace"),
        )

@dataclass
class McpServiceConfig:
    """Configuration for a specific MCP service."""
    server_url: str
    redirect_uris: list[str]
    grant_types: list[str] = field(default_factory=lambda: ["client_credentials", "authorization_code"])
    scope: str = "mcp:tools"
    token_endpoint_auth_method: str = "client_secret_basic"
    redirect_handler: Callable[[str], Awaitable[None]] | None = None
    callback_handler: Callable[[], Awaitable[tuple[str, str | None]]] | None = None

@dataclass
class AppConfig:
    keycloak: KeycloakConfig
    mcp_services: dict[str, McpServiceConfig]

    @classmethod
    def load(cls) -> "AppConfig":
        # Load specific services
        services = {}
        
        # Math Service
        services["math"] = McpServiceConfig(
            server_url=os.getenv("MCP_MATH_URL", os.getenv("MCP_SERVER_URL", "http://127.0.0.1:3000/math/math")),
            redirect_uris=["http://127.0.0.1:3000/math/"],
        )
        
        # HR Policy Service
        services["hr-policy"] = McpServiceConfig(
            server_url=os.getenv("MCP_HR_POLICY_URL", "http://127.0.0.1:3000/hr-policy/hr-policy"),
            redirect_uris=["http://127.0.0.1:3000/hr-policy/"]
        )
        
        return cls(
            keycloak=KeycloakConfig.from_env(),
            mcp_services=services,
        )
        
    def get_service(self, name: str) -> McpServiceConfig:
        if name not in self.mcp_services:
            raise KeyError(f"MCP Service '{name}' not configured.")
        return self.mcp_services[name]
