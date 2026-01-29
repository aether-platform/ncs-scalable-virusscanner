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

テストスイートは、実行環境と依存関係に基づいて大きく2つに分類されています。

### 1. Local Tests (`tests/local/`)

外部サービス（Redis/ClamAV）を必要とせず、モックを使用して実行できる単体テストです。
主に開発中のロジック検証に使用します。

```bash
# 実行例
pytest tests/local/from_consumer/test_handler.py
```

### 2. Integrated Tests (`tests/integrated/`)

Docker環境（Redis, Producer, Consumer, ClamAV）が起動していることを前提とした境界・結合テストです。
`localhost` 経由で実際の通信を検証します。

#### Producer Boundary Test

EnvoyからのgRPCリクエストをシミュレートします。

```bash
# 実行例
python tests/integrated/test_producer.py
```

#### Consumer Boundary Test (E2E)

Redisに直接タスクを投入し、処理フロー全体を検証します。

```bash
# 実行例
python tests/integrated/from_redis/test_injection.py
```

## References

- [Producer README](src/virus_scanner/producer/README.md) - Envoy integration guide
- [Helm Chart](../helm/README.md) - Kubernetes deployment configuration
- [E2E Tests](../../e2e/README.md) - Integration testing guide
