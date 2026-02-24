FROM ubuntu:24.04

# Install Python and dependencies
RUN apt-get update && apt-get install -y \
    python3.12 \
    python3-pip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set python3.12 as default python
RUN ln -s /usr/bin/python3.12 /usr/bin/python

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy dependency files and README (required by pyproject.toml)
COPY pyproject.toml uv.lock README.md ./

# Copy source code
COPY src/ src/

# Install flavor (consumer, producer, or all)
# Build with: docker build --build-arg FLAVOR=consumer .
ARG FLAVOR=all
RUN uv pip install --system --break-system-packages ".[$FLAVOR]"

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Create scan temp directory
RUN mkdir -p /tmp/virusscan && chmod 777 /tmp/virusscan

# Expose ports
# 50051: Producer gRPC (ext_proc)
# 8080: Producer metrics
EXPOSE 50051 8080

# Default command (will be overridden by K8s or build-arg but here we keep a generic one)
CMD ["virus-scanner-handler"]
