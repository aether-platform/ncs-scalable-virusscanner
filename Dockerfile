FROM python:3.11-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy dependency files and README (required by pyproject.toml)
COPY pyproject.toml README.md ./
# COPY uv.lock .

# Copy source code
COPY src/ src/

# Install flavor (consumer, producer, or all)
# Build with: docker build --build-arg FLAVOR=consumer .
ARG FLAVOR=all
RUN uv pip install --system ".[$FLAVOR]"

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Create scan temp directory
RUN mkdir -p /tmp/virusscan && chmod 777 /tmp/virusscan

# Expose ports
# 50051: Producer gRPC (ext_proc)
# 8080: Producer metrics
EXPOSE 50051 8080

# Default: Run Consumer (Handler)
# For Producer: docker run <image> python -m virus_scanner.producer.main
CMD ["virus-scanner-handler", "--redis-host", "localhost", "--redis-port", "6379", "--clamd-url", "tcp://127.0.0.1:3310"]
