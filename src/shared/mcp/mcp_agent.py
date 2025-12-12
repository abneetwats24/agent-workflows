"""
Base MCP Agent with Keycloak OAuth2 client credentials authentication.
"""

from abc import ABC
import asyncio
from datetime import timedelta
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from src.shared.mcp.mcp_client_factory import create_mcp_oauth_provider
from src.config.mcp_config import AppConfig


class BaseMCPAgent(ABC):
    """Base class for MCP agents with Keycloak authentication."""

    @staticmethod
    async def console_redirect_handler(url: str):
        print(f"\n🔐  Please authenticate at: {url}")
        print("    (Click the link or copy-paste it into your browser)")
        print("    After authenticating, you will see a 'code' in the URL or page.")

    @staticmethod
    async def console_callback_handler() -> tuple[str, str | None]:
        print("\n📥  Paste the FULL redirect URL here:")
        print("    (Must comprise the entire URL including 'code' and 'state' parameters)")
        response = input("    URL: ").strip()
        
        # Parse the URL to extract code and state
        if "://" in response or "?" in response:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(response)
            params = parse_qs(parsed.query)
            code = params.get("code", [None])[0]
            state = params.get("state", [None])[0]
            
            if code:
                return code, state
                
        # Fallback: if user still pasted just code, we return it but state will be None
        # leading to the mismatch error we saw.
        return response, None

    def __init__(self, config: AppConfig, service_name: str):
        self.config = config
        self.service_name = service_name
        self.session: ClientSession | None = None
        
        # Apply patches globally at startup (idempotent safe)
        # apply_mcp_patches(discovery_patch=discovery_patch, auth_patch=auth_patch)

    async def connect(self):
        """Connect to the MCP server using client credentials flow."""
        service_config = self.config.get_service(self.service_name)
        
        print(f"🔗 Connecting to MCP server at {service_config.server_url}...")
        print(f"🔐 Using Keycloak at {self.config.keycloak.url}")

        try:
            # Create OAuth provider using factory
            
            # Use configured handlers or default to console
            redirect_handler = getattr(service_config, 'redirect_handler', None) or self.console_redirect_handler
            callback_handler = getattr(service_config, 'callback_handler', None) or self.console_callback_handler
            
            oauth_auth = await create_mcp_oauth_provider(
                server_url=service_config.server_url,
                client_id=self.config.keycloak.client_id,
                client_secret=self.config.keycloak.client_secret,
                redirect_uris=service_config.redirect_uris,
                scope=service_config.scope,
                skip_registration=True,
                grant_types=getattr(service_config, 'grant_types', ["client_credentials"]),
                token_endpoint_auth_method=getattr(service_config, 'token_endpoint_auth_method', "client_secret_post"),
                redirect_handler=redirect_handler,
                callback_handler=callback_handler
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

            print(f"\n✅ Connected to MCP server at {self.config.get_service(self.service_name).server_url}")
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

    async def list_resources(self):
        """List available resources from the server."""
        if not self.session:
            print("❌ Not connected to server")
            return

        try:
            result = await self.session.list_resources()
            if hasattr(result, "resources") and result.resources:
                print("\n📂 Available resources:")
                for i, resource in enumerate(result.resources, 1):
                    print(f"{i}. {resource.name} ({resource.uri})")
                    if resource.description:
                        print(f"   Description: {resource.description}")
                    print(f"   MIME Type: {resource.mimeType}")
                    print()
            else:
                print("No resources available")
        except Exception as e:
            print(f"❌ Failed to list resources: {e}")
            import traceback
            traceback.print_exc()

    async def read_resource(self, uri: str):
        """Read a specific resource."""
        if not self.session:
            print("❌ Not connected to server")
            return

        try:
            print(f"\n📖 Reading resource: {uri}")
            result = await self.session.read_resource(uri)
            print(f"\n✅ Resource content:")
            if hasattr(result, "contents"):
                for content in result.contents:
                    print(f"--- {content.uri} ---")
                    if content.text:
                        print(content.text)
                    else:
                        print(f"[Binary data: {len(content.blob)} bytes]")
            else:
                print(result)
        except Exception as e:
            print(f"❌ Failed to read resource '{uri}': {e}")
            import traceback
            traceback.print_exc()

    async def list_prompts(self):
        """List available prompts from the server."""
        if not self.session:
            print("❌ Not connected to server")
            return

        try:
            result = await self.session.list_prompts()
            if hasattr(result, "prompts") and result.prompts:
                print("\n💬 Available prompts:")
                for i, prompt in enumerate(result.prompts, 1):
                    print(f"{i}. {prompt.name}")
                    if prompt.description:
                        print(f"   Description: {prompt.description}")
                    if hasattr(prompt, "arguments"):
                        print(f"   Arguments: {prompt.arguments}")
                    print()
            else:
                print("No prompts available")
        except Exception as e:
            print(f"❌ Failed to list prompts: {e}")
            import traceback
            traceback.print_exc()

    async def get_prompt(self, prompt_name: str, arguments: dict[str, Any] | None = None):
        """Get a specific prompt."""
        if not self.session:
            print("❌ Not connected to server")
            return

        try:
            print(f"\n📝 Getting prompt '{prompt_name}' with arguments: {arguments}")
            result = await self.session.get_prompt(prompt_name, arguments or {})
            print(f"\n✅ Prompt result:")
            if hasattr(result, "messages"):
                for msg in result.messages:
                    print(f"[{msg.role}] {msg.content.text}")
            else:
                print(result)
        except Exception as e:
            print(f"❌ Failed to get prompt '{prompt_name}': {e}")
            import traceback
            traceback.print_exc()

    async def interactive_loop(self):
        """Run interactive command loop."""
        print("\n🎯 Interactive MCP Client")
        print("Commands:")
        print("  list_tools - List available tools")
        print("  call <tool_name> [args] - Call a tool (args as JSON)")
        print("  list_resources - List available resources")
        print("  read <uri> - Read a resource")
        print("  list_prompts - List available prompts")
        print("  prompt <prompt_name> [args] - Get a prompt (args as JSON)")
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

                elif command == "list_tools" or command == "list":
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

                elif command == "list_resources":
                    await self.list_resources()

                elif command.startswith("read "):
                    parts = command.split(maxsplit=1)
                    uri = parts[1] if len(parts) > 1 else ""
                    if not uri:
                        print("❌ Please specify a resource URI")
                        continue
                    await self.read_resource(uri)

                elif command == "list_prompts":
                    await self.list_prompts()

                elif command.startswith("prompt "):
                    parts = command.split(maxsplit=2)
                    prompt_name = parts[1] if len(parts) > 1 else ""

                    if not prompt_name:
                        print("❌ Please specify a prompt name")
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

                    await self.get_prompt(prompt_name, arguments)

                else:
                    print("❌ Unknown command. Try 'list_tools', 'call', 'list_resources', 'read', 'list_prompts', 'prompt', or 'quit'")

            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except EOFError:
                break
