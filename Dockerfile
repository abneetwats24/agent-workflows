FROM python:3.13-slim

WORKDIR /app

# Install system dependencies if needed (none strictly required for basic python app, but keeping update good practice)
# RUN apt-get update && apt-get install -y --no-install-recommends ... && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
# If you had a lock file like uv.lock or poetry.lock, you would copy it here too.
COPY uv.lock .

# Install dependencies
# Using pip to install from pyproject.toml. 
# We install with [project] dependencies.
RUN pip install --no-cache-dir .

COPY src/ src/
COPY .env.example .

# Create a non-root user for security
RUN useradd -m appuser
USER appuser

CMD ["python", "src/main.py"]
