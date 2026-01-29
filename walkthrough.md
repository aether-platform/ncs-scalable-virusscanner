# Technical Specification: High-Availability Streaming Virus Scanner

This document describes the high-level protocols and architecture of the Aether NCS Virus Scanner. It is intended for external developers who wish to implement custom producers or integrate with the scanning infrastructure.

## 1. Zero-Downtime Sequential Update (HA-Update)

To ensure zero-downtime during ClamAV database updates (which require a `RELOAD` command that temporarily blocks the engine), the system employs a coordinated sequential update strategy.

### Protocol Flow

1.  **Epoch Monitoring**: Each node reports its current version (Epoch) via Redis heartbeats: `clamav:heartbeat:<pod_name>`.
2.  **Target Epoch**: An external process (e.g., database updater) sets `clamav:target_epoch` to a new version.
3.  **Surge Scaling**: If only one node is active, the node requests a "Surge" via Redis `clamav:scaling_request`, which triggers a KEDA scale-out (scale to 2).
4.  **Distributed Lock**: Nodes attempt to acquire a Redis lock: `clamav:update_lock`. Only one node updates at a time.
5.  **Sequential Reload**:
    - The node with the lock performs `clamd RELOAD`.
    - It pings ClamAV until the engine is back online.
    - It updates its heartbeat with the new Epoch.
    - It releases the lock.
6.  **Scale Down**: Once all nodes reflect the target epoch in their heartbeats, the surge request is cleared, allowing KEDA to scale back to the normal replica count.

## 2. Real-Time Streaming (STREAM Mode)

The scanner supports a "Follower-style" streaming mode where it processes data chunks as they arrive in Redis, minimizing Turn-Around-Time (TAT).

### Protocol Specification (Low-level)

To use STREAM mode without the SDK, a Producer must follow this sequence:

| Step | Action           | Redis Command / Key                                            |
| :--- | :--------------- | :------------------------------------------------------------- |
| 1    | **Enqueue Task** | `LPUSH scan_priority "task_id\|STREAM\|timestamp\|chunks_key"` |
| 2    | **Stream Data**  | `RPUSH chunks_key <binary_data>` (repeat for each chunk)       |
| 3    | **Signal Done**  | `SET chunks_key:done "1"`                                      |
| 4    | **Wait Result**  | `BRPOP result:task_id 30`                                      |

### Symmetrical Abstraction (Shared SDK)

The `virus-scanner` package provides a shared SDK in `virus_scanner.common.providers`. Both Producers and Consumers can use these classes to handle the protocol logic symmetrically:

```python
from virus_scanner.common.providers import RedisStreamProvider

# Producer Side (Client/SDK Usage)
provider = RedisStreamProvider(redis_client, chunks_key="my_upload")
for chunk in large_file_iterator():
    provider.push_chunk(chunk)
provider.finalize_push()
# Enqueue task...
```

### Memory Safety and Reliability

The Consumer uses the atomic `BLMOVE` (source: `chunks_key`, dest: `chunks_key:verified`) pattern.

- **Constant Memory**: The Consumer only ever holds one chunk (default ~1MB) in memory at a time, regardless of file size.
- **Follower Processing**: Scanning happens in parallel with the upload. The consumer "chases" the producer's tail.

## 3. Non-Destructive Data Relay

Verified data is preserved in Redis to avoid redundant transfers.

- **Clean Files**: Chunks are moved to `{chunks_key}:verified`. The scan result returns this key as `data_key`. The data is persisted for 1 hour.
- **Infected Files**: If a virus is detected, the `{chunks_key}:verified` list is **immediately purged** to ensure no contaminated data remains on the server.

---

## Technical Specs Summary

- **Task Format**: `task_id|mode|push_time|content`
- **Result Format**: JSON object in `result:task_id`
  ```json
  {
    "status": "CLEAN" | "INFECTED" | "ERROR",
    "virus": "VirusName" | null,
    "data_key": "chunks_key:verified" | null,
    "metrics": { "scan_ms": 123, "total_tat_ms": 456 }
  }
  ```
- **Metrics**: Prometheus metrics available on `:8080/metrics`.
  - `virusscan_priority_tat_ms`: Last processed TAT for priority queue.
  - `virusscan_normal_tat_ms`: Last processed TAT for normal queue.
  - `virusscan_ingest_tat_ms`: Last ingest (upload) duration from Producer's perspective.

## 4. Service Abstraction (StreamScannerService)

The Producer employs a high-level `StreamScannerService` to encapsulate domain logic:

- **Session Management**: Automatically tracks request start times for precise E2E TAT.
- **Task Orchestration**: Handles the choosing of providers and emitting to Redis.
- **Metrics Ingestion**: Automatically records ingest performance metrics upon completion.

## 5. Shared Configuration (SDK)

The project uses a consolidated settings structure in `virus_scanner.common.settings`. Both components share:

- `BaseSettings`: Redis connection and temporary directory paths.
