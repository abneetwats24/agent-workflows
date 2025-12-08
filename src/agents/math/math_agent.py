#!/usr/bin/env python3
"""
MCP client with Keycloak OAuth2 client credentials authentication.

This client connects to an MCP server using client credentials flow (no user interaction needed).
"""

import asyncio
from datetime import timedelta
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# Ensure project root is in path for imports
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

# Import new modular components
from src.shared.mcp.mcp_utils import apply_mcp_patches
from src.shared.mcp.mcp_client_factory import create_mcp_oauth_provider
from src.config.mcp_config import AppConfig

# Apply patches globally at startup
apply_mcp_patches()

class MCPKeycloakClient:
    """MCP client with Keycloak client credentials authentication."""

    def __init__(
        self,
        config: AppConfig
    ):
        self.config = config
        self.session: ClientSession | None = None

    async def connect(self):
        """Connect to the MCP server using client credentials flow."""
        service_config = self.config.get_service("math")
        
        print(f"🔗 Connecting to MCP server at {service_config.server_url}...")
        print(f"🔐 Using Keycloak at {self.config.keycloak.url}")

        try:
            # Create OAuth provider using factory
            oauth_auth = await create_mcp_oauth_provider(
                server_url=service_config.server_url,
                client_id=self.config.keycloak.client_id,
                client_secret=self.config.keycloak.client_secret,
                redirect_uris=service_config.redirect_uris,
                scope=service_config.scope,
                skip_registration=True
            )

            print("📡 Opening StreamableHTTP transport with client credentials auth...")
            
            async with streamablehttp_client(
                url=service_config.server_url,
                auth=oauth_auth,
                timeout=timedelta(seconds=60),
            ) as (read_stream, write_stream, get_session_id):
                await self._run_session(read_stream, write_stream, get_session_id)

        except Exception as e:
            print(f"❌ Failed to connect: {e}")
            import traceback
            traceback.print_exc()

    async def _run_session(self, read_stream, write_stream, get_session_id):
        """Run the MCP session with the given streams."""
        print("🤝 Initializing MCP session...")
        async with ClientSession(read_stream, write_stream) as session:
            self.session = session
            print("⚡ Starting session initialization...")
            await session.initialize()
            print("✨ Session initialization complete!")

            print(f"\n✅ Connected to MCP server at {self.config.get_service('math').server_url}")
            if get_session_id:
                session_id = get_session_id()
                if session_id:
                    print(f"📋 Session ID: {session_id}")

            # Run interactive loop
            await self.interactive_loop()

    async def list_tools(self):
        """List available tools from the server."""
        if not self.session:
            print("❌ Not connected to server")
            return

        try:
            result = await self.session.list_tools()
            if hasattr(result, "tools") and result.tools:
                print("\n📋 Available tools:")
                for i, tool in enumerate(result.tools, 1):
                    print(f"{i}. {tool.name}")
                    if tool.description:
                        print(f"   Description: {tool.description}")
                    if hasattr(tool, "inputSchema"):
                        print(f"   Input schema: {tool.inputSchema}")
                    print()
            else:
                print("No tools available")
        except Exception as e:
            print(f"❌ Failed to list tools: {e}")
            import traceback
            traceback.print_exc()

    async def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None):
        """Call a specific tool."""
        if not self.session:
            print("❌ Not connected to server")
            return

        try:
            print(f"\n🔧 Calling tool '{tool_name}' with arguments: {arguments}")
            result = await self.session.call_tool(tool_name, arguments or {})
            print(f"\n✅ Tool '{tool_name}' result:")
            if hasattr(result, "content"):
                for content in result.content:
                    if content.type == "text":
                        print(content.text)
                    else:
                        print(content)
            else:
                print(result)
        except Exception as e:
            print(f"❌ Failed to call tool '{tool_name}': {e}")
            import traceback
            traceback.print_exc()

    async def interactive_loop(self):
        """Run interactive command loop."""
        print("\n🎯 Interactive MCP Client")
        print("Commands:")
        print("  list - List available tools")
        print("  call <tool_name> [args] - Call a tool (args as JSON)")
        print("  quit - Exit the client")
        print()

        while True:
            try:
                command = input("mcp> ").strip()

                if not command:
                    continue

                if command == "quit":
                    print("👋 Goodbye!")
                    break

                elif command == "list":
                    await self.list_tools()

                elif command.startswith("call "):
                    parts = command.split(maxsplit=2)
                    tool_name = parts[1] if len(parts) > 1 else ""

                    if not tool_name:
                        print("❌ Please specify a tool name")
                        continue

                    # Parse arguments (simple JSON format)
                    arguments = {}
                    if len(parts) > 2:
                        import json
                        try:
                            arguments = json.loads(parts[2])
                        except json.JSONDecodeError:
                            print("❌ Invalid arguments format (expected JSON)")
                            continue

                    await self.call_tool(tool_name, arguments)

                else:
                    print("❌ Unknown command. Try 'list', 'call <tool_name>', or 'quit'")

            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except EOFError:
                break


async def main():
    """Main entry point."""
    # Load configuration
    config = AppConfig.load()

    print("🚀 MCP Client with Keycloak Authentication")
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
    client = MCPKeycloakClient(config=config)
    await client.connect()


def cli():
    """CLI entry point."""
    asyncio.run(main())


if __name__ == "__main__":
    cli()
