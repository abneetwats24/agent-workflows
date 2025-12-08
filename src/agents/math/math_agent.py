#!/usr/bin/env python3
"""
MCP client with Keycloak OAuth2 client credentials authentication.

This client connects to an MCP server using client credentials flow (no user interaction needed).
"""

import asyncio
import os
from datetime import timedelta
from typing import Any
from dotenv import load_dotenv

load_dotenv()

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
import mcp.client.auth.oauth2

# ------------------------------------------------------------------------------
# Monkeypatch to fix discovery URL when using path-based routing (e.g. /math)
# The default implementation resets the path to root when constructing .well-known URLs.
# ------------------------------------------------------------------------------
_original_build_discovery_urls = mcp.client.auth.oauth2.build_protected_resource_metadata_discovery_urls

def masked_build_protected_resource_metadata_discovery_urls(headers, server_url):
    urls = _original_build_discovery_urls(headers, server_url)
    # If server_url has a path segment (e.g. /math/math or /math), ensure it's preserved
    # The original function often returns [root/.well-known/..., root/.well-known/...]
    
    # We want to inject the path-aware endpoint if it's missing or incorrect.
    # Simple heuristic: if server_url contains a path, ensure we look for .well-known under that path.
    
    from urllib.parse import urljoin, urlparse
    
    parsed = urlparse(server_url)
    path = parsed.path
    if path and path != "/":
        # Ensure path ends with slash for urljoin to work comfortably or just handle it manually
        # E.g. /math/math -> /math/math/.well-known/...
        # But commonly we might want /math/.well-known/... if /math is the mount.
        # User said: http://127.0.0.1:3000/math/.well-known/oauth-protected-resource works.
        
        # Let's add the path-specific discovery URL to the front of the list
        # Assuming the mount point is the first segment or we just use the full path provided.
        # If server_url is .../math/math, we might want .../math/math/.well-known/... ??
        # Or just .../math/.well-known/...
        
        # Based on user verified curl:
        # http://127.0.0.1:3000/math/.well-known/oauth-protected-resource
        
        # Let's try to deduce the mount base.
        # If we trust the server_url to be correct, we can try to append .well-known to it.
        
        # We will try adding a URL that respects the given server_url's path.
        # Strip trailing slash
        base = server_url.rstrip('/')
        
        # Heuristic 1: If it ends in /math/math, maybe the mount is /math?
        # User config: server_url = "http://127.0.0.1:3000/math/math"
        # User target: "http://127.0.0.1:3000/math/.well-known/oauth-protected-resource"
        
        # It seems the mount is `/math`.
        
        # Let's add a robust check.
        new_urls = []
        
        # 1. Try server_url + /.well-known/... (path relative)
        if base.endswith('/math/math'):
             # Special case for this user if generic fails? 
             # Or generic: take parent of the resource?
             parent = base.rpartition('/')[0] # http://.../math
             new_urls.append(f"{parent}/.well-known/oauth-protected-resource")
        
        # Add a generic one just in case: explicit path based
        new_urls.append(f"{base}/.well-known/oauth-protected-resource")
        
        # Add original ones as fallback
        new_urls.extend(urls)
        
        return new_urls
        
    return urls

mcp.client.auth.oauth2.build_protected_resource_metadata_discovery_urls = masked_build_protected_resource_metadata_discovery_urls

# ------------------------------------------------------------------------------
# Monkeypatch to support client_credentials grant type
# The library seems to hardcode authorization_code flow in _perform_authorization
# ------------------------------------------------------------------------------
import httpx
from mcp.client.auth import OAuthClientProvider

_original_perform_authorization = OAuthClientProvider._perform_authorization

async def masked_perform_authorization(self) -> httpx.Request:
    # Check if we should use client_credentials
    # We can check self.context.client_metadata.grant_types
    grant_types = self.context.client_metadata.grant_types
    if "client_credentials" in grant_types:
        print("🔓 Performing client_credentials grant flow...")
        
        # We need the token endpoint.
        # It should be available in self.context.oauth_metadata or we fallback to our manual one if needed.
        # Given we skipped dynamic registration properly (hopefully), oauth_metadata might be populated if discovery worked.
        
        token_endpoint = None
        if self.context.oauth_metadata:
            token_endpoint = str(self.context.oauth_metadata.token_endpoint)
        
        if not token_endpoint:
            # Fallback based on user config if discovery didn't fully populate dynamic metadata?
            # But discovery should have worked now.
            # If not, let's try to reconstruct it or error.
            # But wait, we populate client_info manually in my previous step, but that's Client Information, not Server Metadata.
            # Server metadata comes from discovery.
            pass
            
        if not token_endpoint:
             # If we can't find it dynamically, let's use the known Keycloak pattern 
             # But really we expect it to be there.
             # Let's fail hard if not found so we know.
             if not self.context.oauth_metadata:
                 print("⚠️ No OAuth metadata found in context. Discovery might have failed or not completed?")
             raise ValueError("Token endpoint not found for client_credentials flow")

        # Construct payload
        data = {
            "grant_type": "client_credentials",
            "scope": self.context.client_metadata.scope or "mcp:tools"
        }
        
        # Add client credentials
        # Supports client_secret_post (in body) or client_secret_basic (header)
        auth_method = self.context.client_metadata.token_endpoint_auth_method
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        
        if auth_method == "client_secret_post":
            data["client_id"] = self.context.client_info.client_id
            data["client_secret"] = self.context.client_info.client_secret
        elif auth_method == "client_secret_basic":
            import base64
            auth_str = f"{self.context.client_info.client_id}:{self.context.client_info.client_secret}"
            b64_auth = base64.b64encode(auth_str.encode()).decode()
            headers["Authorization"] = f"Basic {b64_auth}"
            
        # Create request
        request = httpx.Request("POST", token_endpoint, data=data, headers=headers)
        return request

    return await _original_perform_authorization(self)

OAuthClientProvider._perform_authorization = masked_perform_authorization

# ------------------------------------------------------------------------------



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
                "scope": "mcp:tools",  # Adjust scopes as needed
                "redirect_uris": ["http://127.0.0.1:3000/math/"],
            }

            print(f"📝 Token endpoint: {token_endpoint}")

            # Pre-populate client info to skip dynamic registration
            # The server policy rejects dynamic registration, and we already have credentials.
            storage = InMemoryTokenStorage()
            client_info = OAuthClientInformationFull(
                client_id=self.client_id,
                client_secret=self.client_secret,
                redirect_uris=[client_metadata_dict["redirect_uris"][0]],
                token_endpoint_auth_method="client_secret_post",
                grant_types=["client_credentials"],
                scope=client_metadata_dict["scope"]
            )
            await storage.set_client_info(client_info)

            # Create OAuth provider with client credentials
            oauth_auth = OAuthClientProvider(
                server_url=self.server_url,
                client_metadata=OAuthClientMetadata.model_validate(client_metadata_dict),
                storage=storage,
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
            # Try to print token debug info
            if self.session and hasattr(self.session, "auth_provider"):
                 # Accessing internal structure might be hard, but let's try via storage
                 # We need reference to storage used.
                 pass
            
            # The storage was created in connect(), we don't have reference in self unless we saved it.
            # But wait, we can't easily access local variable 'oauth_auth' here.
            # I should capture it.
            import traceback
            traceback.print_exc()

            # Inspect token if possible (we don't have handle here easily without massive refactor)
            # Let's trust my deduction for now.

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
    server_url = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:3000/math/math")
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
    if client_id == "abneet_mcp_client":
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
