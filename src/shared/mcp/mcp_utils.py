"""
Shared utilities for MCP clients.
Contains monkeypatches to fix discovery URLs and enable Client Credentials Grant flow.
"""
import mcp.client.auth.oauth2
from mcp.client.auth import OAuthClientProvider
import httpx
from urllib.parse import urlparse
import sys

def apply_mcp_patches(discovery_patch: bool = False, auth_patch: bool = True):
    """
    Apply monkeypatches to the MCP library.
    
    Args:
        discovery_patch: If True, patch discovery URL construction to look for .well-known paths.
        auth_patch: If True, patch OAuth provider to support Client Credentials Grant flow.
    """
    # Track which patches are applied
    if not hasattr(sys, "_mcp_patches_applied"):
        sys._mcp_patches_applied = set()
    
    applied = sys._mcp_patches_applied
    
    if discovery_patch and "discovery" not in applied:
        print("🩹 Applying MCP discovery patch...")
        mcp.client.auth.oauth2.build_protected_resource_metadata_discovery_urls = _masked_build_protected_resource_metadata_discovery_urls
        applied.add("discovery")
        
    if auth_patch and "auth" not in applied:
        print("🩹 Applying MCP client credentials auth patch...")
        OAuthClientProvider._perform_authorization = _masked_perform_authorization
        applied.add("auth")
    
    if discovery_patch or auth_patch:
        print("✅ MCP patches applied.")


# ------------------------------------------------------------------------------
# Monkeypatch 1: Fix discovery URL
# ------------------------------------------------------------------------------
_original_build_discovery_urls = mcp.client.auth.oauth2.build_protected_resource_metadata_discovery_urls

def _masked_build_protected_resource_metadata_discovery_urls(headers, server_url):
    urls = _original_build_discovery_urls(headers, server_url)
    
    parsed = urlparse(server_url)
    path = parsed.path
    if path and path != "/":
        base = server_url.rstrip('/')
        new_urls = []
        
        # General heuristics: try adding .well-known at the current path and all parent paths
        # This covers:
        # 1. http://.../math/math  -> .../math/.well-known/...
        # 2. http://.../hr-policy  -> .../hr-policy/.well-known/...
        
        # Add exact path first
        new_urls.append(f"{base}/.well-known/oauth-protected-resource")
        
        # Walk up the path
        # /math/math -> /math -> /
        # We stop before root generally, as original function covers root.
        
        current_base = base
        while True:
            parent = current_base.rpartition('/')[0]
            if not parent or parent == parsed.scheme + "://" + parsed.netloc:
                break
                
            new_urls.append(f"{parent}/.well-known/oauth-protected-resource")
            current_base = parent
            
        new_urls.extend(urls)
        return new_urls
        
    return urls


# ------------------------------------------------------------------------------
# Monkeypatch 2: Client Credentials Flow
# ------------------------------------------------------------------------------
_original_perform_authorization = OAuthClientProvider._perform_authorization

async def _masked_perform_authorization(self) -> httpx.Request:
    grant_types = self.context.client_metadata.grant_types
    if "client_credentials" in grant_types:
        print("🔓 Performing client_credentials grant flow...")
        
        token_endpoint = None
        if self.context.oauth_metadata:
            token_endpoint = str(self.context.oauth_metadata.token_endpoint)
        
        if not token_endpoint:
             if not self.context.oauth_metadata:
                 print("⚠️ No OAuth metadata found in context. Discovery might have failed or not completed?")
             raise ValueError("Token endpoint not found for client_credentials flow")

        data = {
            "grant_type": "client_credentials",
            "scope": self.context.client_metadata.scope or "mcp:tools"
        }
        
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
            
        request = httpx.Request("POST", token_endpoint, data=data, headers=headers)
        return request

    return await _original_perform_authorization(self)
