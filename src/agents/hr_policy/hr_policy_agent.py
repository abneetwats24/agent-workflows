#!/usr/bin/env python3
"""
MCP client for HR Policy Service with Keycloak OAuth2 client credentials authentication.
"""
import asyncio
import sys
import os
from dotenv import load_dotenv

# Ensure project root is in path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from langchain_openai import ChatOpenAI
from langchain_community.callbacks import get_openai_callback
from langchain.agents import create_agent
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_mcp_adapters.resources import load_mcp_resources
from langchain_core.messages import HumanMessage, SystemMessage

from src.config.mcp_config import AppConfig
from src.shared.mcp.mcp_agent import BaseMCPAgent

load_dotenv()

class MCPHRPolicyClient(BaseMCPAgent):
    """MCP client for HR Policy Service."""

    def __init__(self, config: AppConfig):
        super().__init__(config, service_name="hr-policy")

    async def interactive_loop(self):
        """Run interactive chat loop with LLM agent."""
        if not os.environ.get("OPENAI_API_KEY"):
            print("❌ OPENAI_API_KEY environment variable is not set.")
            print("Please set it to use the LLM-enhanced agent.")
            return

        print("\n🤖 Initializing LLM Agent...")
        
        try:
            # Initialize LLM
            model = ChatOpenAI(model="gpt-4o")

            # Load tools from MCP session (if any)
            tools = await load_mcp_tools(self.session)
            print(f"🛠️  Loaded {len(tools)} tools from MCP server")

            # Load resources from MCP session
            print("📚 Loading resources from MCP server...")
            resource_blobs = await load_mcp_resources(self.session)
            print(f"✅ Loaded {len(resource_blobs)} resources")

            # Format resources for system context
            resource_context = "You are an HR Policy Assistant. You have access to the following policies:\n\n"
            for blob in resource_blobs:
                # content can be bytes or str in specific blob types, 
                # but LangChain Blob usually has as_string()
                try:
                    content = blob.as_string()
                    # Try to find a name/source if available in metadata
                    source = blob.source or "Unknown Policy"
                    resource_context += f"--- POLICY: {source} ---\n{content}\n\n"
                except Exception as e:
                    print(f"⚠️ Failed to read blob: {e}")

            resource_context += "Answer user questions based on these policies. " \
                                "If a policy is not listed, say you don't have information about it."

            system_message = SystemMessage(content=resource_context)

            # Create React agent
            agent = create_agent(model, tools)

            print("\n💬 HR Policy Agent Ready! (Type 'quit' or 'exit' to stop)")
            print("You can ask about available policies or specific questions.")
            
            # Start conversation with system context
            messages = [system_message]
            
            while True:
                user_input = input("\nUser: ").strip()
                if not user_input:
                    continue
                
                if user_input.lower() in ["quit", "exit"]:
                    print("👋 Goodbye!")
                    break

                messages.append(HumanMessage(content=user_input))

                print("\nAgent: ", end="", flush=True)
                
                with get_openai_callback() as cb:
                    response = await agent.ainvoke({"messages": messages})
                    print(f"\n[Token Usage]: {cb}")
                
                # Update history
                messages = response["messages"]
                
                # Print response
                if messages and hasattr(messages[-1], "content"):
                    print(messages[-1].content)
                else:
                    print("(No response)")

        except Exception as e:
            print(f"\n❌ Error initializing or running agent: {e}")
            import traceback
            traceback.print_exc()


async def main():
    """Main entry point."""
    # Load configuration
    config = AppConfig.load()

    print("🚀 HR Policy MCP Client with Keycloak Authentication")
    print(f"📍 MCP Server: {config.get_service('hr-policy').server_url}")
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
    client = MCPHRPolicyClient(config=config)
    await client.connect()


def cli():
    """CLI entry point."""
    asyncio.run(main())


if __name__ == "__main__":
    cli()
