# Virus Scanner

Redis-based virus scanning service with Producer (Envoy ext_proc) and Consumer (ClamAV worker) components.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Egress Flow                              │
└─────────────────────────────────────────────────────────────────┘

Client Request
     │
     ├──> Envoy Gateway (Egress)
     │         │
     │         ├──> Producer (ext_proc gRPC) ──┐
     │         │                                 │
     │         └──> Upstream (if clean) ────────┤
     │                                           │
     └──> Block (403) if infected               │
                                                 │
                                                 ▼
                                          Redis Queue
                                          (scan_priority)
                                          (scan_normal)
                                                 │
                                                 ▼
                                          Consumer Pod
                                          ├─ Scanner (Python)
                                          └─ ClamAV (clamd)
                                                 │
                                                 ▼
                                          Result → Redis
```

## Components

### Producer (Envoy External Processor)

Envoy の `ext_proc` フィルターとして動作し、リクエストボディをインターセプトしてウイルススキャンを実行します。

- **役割**: リクエストボディをRedisキューに投入し、スキャン結果を待機
- **実装**: gRPC service (`src/virus_scanner/producer/main.py`)
- **デプロイ**: Envoy Gateway の Sidecar または独立サービス
- **ポート**: 50051 (gRPC), 8080 (metrics)

### Consumer (Request Handler)

RedisキューからウイルススキャンタスクをPopし、Pod内のClamAV (clamd) サイドカーへリクエストを転送する Request Handler です。

- **役割**: Redis キューからタスクを取得し、ClamAV でスキャン
- **実装**: Python worker with Dependency Injector (`src/virus_scanner/consumer/main.py`)
- **接続**: `tcp://host:port` または `unix:///path/to/socket` 形式の CLAMD_URL に対応
- **デプロイ**: KEDA ScaledObject による自動スケーリング対応

## Package Structure

単一の Python パッケージ `virus-scanner` で、optional dependencies (extras) により役割を分離：

```toml
[project.optional-dependencies]
consumer = ["clamd", "click", "dependency-injector"]
producer = ["grpcio", "grpcio-tools"]
all = ["virus-scanner[consumer,producer]"]
```

### Installation

```bash
# Install Consumer dependencies only
uv pip install '.[consumer]'

# Install Producer dependencies only
uv pip install '.[producer]'

# Install all dependencies
uv pip install '.[all]'
```

## Docker Build

Use `--build-arg FLAVOR=<flavor>` to build optimized images:

```bash
# Producer-only image (for Envoy sidecar)
docker build --build-arg FLAVOR=producer -t virus-scanner:producer .

# Consumer-only image (for ClamAV workers)
docker build --build-arg FLAVOR=consumer -t virus-scanner:consumer .

# All-in-one image (default)
docker build -t virus-scanner:all .
```

## Usage

### Producer (Envoy ext_proc)

```bash
docker run -p 50051:50051 -p 8080:8080 \
  -e REDIS_HOST=redis \
  virus-scanner:producer virus-scanner-producer
```

### Consumer (ClamAV Worker)

```bash
docker run \
  -e REDIS_HOST=redis \
  -e CLAMD_URL=tcp://127.0.0.1:3310 \
  virus-scanner:consumer virus-scanner-handler --redis-host redis --clamd-url tcp://clamav:3310
```

## Local Development

### Consumer

```bash
# Install dependencies
uv pip install -e '.[consumer]'

# Run with Docker Compose
docker-compose up
```

### Producer

```bash
# Install dependencies
uv pip install -e '.[producer]'

# Generate Envoy protos (one-time)
./generate_protos.sh

# Run Producer
virus-scanner-producer
```

## Testing

テストは境界ごとに分離されています：

```
tests/
├── from_redis/        # Producer境界テスト（Redisから投入）
│   └── test_injection.py
└── from_consumer/     # Consumer境界テスト（Consumer内部）
```

### Producer Boundary Tests (from_redis)

Redis経由でタスクを投入し、end-to-endの動作を検証：

```bash
# Docker Composeで全サービス起動
docker-compose up -d

# テスト実行
python tests/from_redis/test_injection.py
```

### Consumer Boundary Tests (from_consumer)

Consumer内部のロジックを単体テスト（準備中）。

## References

- [Producer README](src/virus_scanner/producer/README.md) - Envoy integration guide
- [Helm Chart](../helm/README.md) - Kubernetes deployment configuration
- [E2E Tests](../../e2e/README.md) - Integration testing guide
