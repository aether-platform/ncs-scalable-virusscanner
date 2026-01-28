# Virus Scanner Producer (Envoy External Processor)

gRPC service that acts as an Envoy External Processor for virus scanning.

## Architecture

Producer integrates with Envoy as an `ext_proc` filter:

```
Client → Envoy → Producer (ext_proc) → Redis Queue → Consumer → ClamAV
                    ↓
                  Block if infected
```

## Features

- **Envoy Integration**: gRPC External Processor service
- **Priority Queueing**: Supports `X-Priority: high` header
- **Large File Handling**: Files >10MB stored on shared filesystem
- **Synchronous Scanning**: Waits for scan result before allowing request
- **Metrics**: Prometheus-compatible `/metrics` endpoint on port 8080
- **Health Check**: `/health` endpoint

## Running

### Development

```bash
# Install with Producer dependencies
uv pip install -e '.[producer]'

# Generate protos first (one-time)
./generate_protos.sh

# Run Producer
uv run virus-scanner-producer
```

### Docker

Build with specific flavor to reduce image size:

```bash
# Build Producer-only image
docker build --build-arg FLAVOR=producer -t virus-scanner:producer .

# Build Consumer-only image
docker build --build-arg FLAVOR=consumer -t virus-scanner:consumer .

# Build with all dependencies (default)
docker build -t virus-scanner:all .

# Run as Producer
docker run -p 50051:50051 -p 8080:8080 \
  -e REDIS_HOST=redis \
  virus-scanner:producer virus-scanner-producer

# Run as Consumer
docker run \
  -e REDIS_HOST=redis \
  virus-scanner:consumer virus-scanner-handler --redis-host redis
```

## Environment Variables

- `REDIS_HOST`: Redis hostname (default: localhost)
- `REDIS_PORT`: Redis port (default: 6379)
- `SCAN_TMP_DIR`: Temp directory for large files (default: /tmp/virusscan)
- `SCAN_FILE_THRESHOLD_MB`: File size threshold (default: 10)

## Envoy Configuration

```yaml
http_filters:
  - name: envoy.filters.http.ext_proc
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
      grpc_service:
        envoy_grpc:
          cluster_name: virus_scanner_producer
      processing_mode:
        request_header_mode: SEND
        request_body_mode: BUFFERED
```

## Task Format

Producer enqueues tasks to Redis:

```
taskID|MODE|TIMESTAMP|CONTENT
```

- **MODE**: `BODY` (inline) or `PATH` (file path)
- **TIMESTAMP**: nanoseconds since epoch
- **CONTENT**: content string or file path
