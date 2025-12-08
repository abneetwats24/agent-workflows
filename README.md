# Agent Workflows

This project implements agentic workflows using LangChain, LangGraph, and the Model Context Protocol (MCP).

## Prerequisites

- Python 3.13+
- Docker & Docker Compose (optional, for containerized execution)

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd agent-workflows
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install .
   ```

4. Configure environment:
   Copy `.env.example` to `.env` and fill in the required values.
   ```bash
   cp .env.example .env
   ```

## Running the Application

### Local
```bash
python src/main.py
```

### Docker
```bash
docker compose up --build
```

## Adding a New MCP Client

To add a new Model Context Protocol (MCP) client to the application, you need to register it in the configuration.

1. Open `src/config/mcp_config.py`.
2. Locate the `AppConfig.load` method.
3. Add a new entry to the `services` dictionary using `McpServiceConfig`.

**Example:**

If you want to add a "weather" service running on port 8080:

```python
# src/config/mcp_config.py

# ... inside AppConfig.load method ...

# Weather Service
services["weather"] = McpServiceConfig(
    server_url=os.getenv("MCP_WEATHER_URL", "http://127.0.0.1:8080/weather/weather"),
    redirect_uris=["http://127.0.0.1:8080/weather/"]
)
```

4. (Optional) Add the corresponding environment variable `MCP_WEATHER_URL` to your `.env` file to allow configuration overrides.
