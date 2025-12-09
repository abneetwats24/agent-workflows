#!/usr/bin/env python3
"""
MCP client for Math Service with Keycloak OAuth2 client credentials authentication.
"""
import asyncio
import sys
import os

# Ensure project root is in path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from src.config.mcp_config import AppConfig
from src.shared.mcp.mcp_agent import BaseMCPAgent


class MCPMathClient(BaseMCPAgent):
    """MCP client for Math Service."""

    def __init__(self, config: AppConfig):
        super().__init__(config, service_name="math")


async def main():
    """Main entry point."""
    # Load configuration
    config = AppConfig.load()

    print("🚀 Math MCP Client with Keycloak Authentication")
    print(f"📍 MCP Server: {config.get_service('math').server_url}")
    print(f"🔐 Keycloak: {config.keycloak.url}")
    print(f"🏢 Realm: {config.keycloak.realm}")
    print(f"👤 Client ID: {config.keycloak.client_id}")
    print()

    # Validate required credentials
    if config.keycloak.client_id == "abneet_mcp_client":
        print("⚠️  Warning: Using default credentials!")
        print("⚠️  Set KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET environment variables")
        print()

    # Create and connect client
    client = MCPMathClient(config=config)
    await client.connect()


def cli():
    """CLI entry point."""
    asyncio.run(main())


if __name__ == "__main__":
    cli()
