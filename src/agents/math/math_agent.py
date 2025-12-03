#!/usr/bin/env python3
"""
MCP client with Keycloak OAuth2 client credentials authentication.

This client connects to an MCP server using client credentials flow (no user interaction needed).
"""

import asyncio
import os
from datetime import timedelta
from typing import Any

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken


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


class MCPKeycloakClient:
    """MCP client with Keycloak client credentials authentication."""

    def __init__(
        self,
        server_url: str,
        keycloak_url: str,
        client_id: str,
        client_secret: str,
        realm: str = "openspace",
    ):
        self.server_url = server_url
        self.keycloak_url = keycloak_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.realm = realm
        self.session: ClientSession | None = None

    async def connect(self):
        """Connect to the MCP server using client credentials flow."""
        print(f"🔗 Connecting to MCP server at {self.server_url}...")
        print(f"🔐 Using Keycloak at {self.keycloak_url}")

        try:
            # Build the token endpoint URL from Keycloak realm
            token_endpoint = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
            
            # Client metadata for client credentials flow
            client_metadata_dict = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "token_endpoint_auth_method": "client_secret_post",
                "grant_types": ["client_credentials"],
                "scope": "openid email profile mcp:tools",  # Adjust scopes as needed
                "redirect_uris": ["http://127.0.0.1:3000/math/"],
            }

            print(f"📝 Token endpoint: {token_endpoint}")

            # Create OAuth provider with client credentials
            oauth_auth = OAuthClientProvider(
                server_url=self.server_url,
                client_metadata=OAuthClientMetadata.model_validate(client_metadata_dict),
                storage=InMemoryTokenStorage(),
                redirect_handler=None,
                callback_handler=None
            )

            print("📡 Opening StreamableHTTP transport with client credentials auth...")
            
            async with streamablehttp_client(
                url=self.server_url,
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

            print(f"\n✅ Connected to MCP server at {self.server_url}")
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
    # Configuration from environment variables or defaults
    server_url = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:3000/math/")
    keycloak_url = os.getenv("KEYCLOAK_URL", "http://192.168.10.7:5555")
    client_id = os.getenv("KEYCLOAK_CLIENT_ID", "abneet_mcp_client")
    client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET", "REMOVED")
    realm = os.getenv("KEYCLOAK_REALM", "openspace")

    print("🚀 MCP Client with Keycloak Authentication")
    print(f"📍 MCP Server: {server_url}")
    print(f"🔐 Keycloak: {keycloak_url}")
    print(f"🏢 Realm: {realm}")
    print(f"👤 Client ID: {client_id}")
    print()

    # Validate required credentials
    if client_id == "abneet_mcp_client" or client_secret == "REMOVED":
        print("⚠️  Warning: Using default credentials!")
        print("⚠️  Set KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET environment variables")
        print()

    # Create and connect client
    client = MCPKeycloakClient(
        server_url=server_url,
        keycloak_url=keycloak_url,
        client_id=client_id,
        client_secret=client_secret,
        realm=realm,
    )
    await client.connect()


def cli():
    """CLI entry point."""
    asyncio.run(main())


if __name__ == "__main__":
    cli()
