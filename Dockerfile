FROM python:3.11-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy dependency files and README (required by pyproject.toml)
COPY pyproject.toml README.md ./
# COPY uv.lock .

# Copy source code
COPY src/ src/

# Install the project and its dependencies
RUN uv pip install --system .

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Entry point using the console script defined in pyproject.toml
CMD ["virus-scanner-handler"]
