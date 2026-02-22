# Aether Platform: Virus Scan Package

Internal implementation of the modular virus scanning service.

## Package Structure

The package is organized into three main components:

- **`producer/`**: The interception layer.
  - Implements gRPC `ext_proc` (Envoy) and ICAP (Squid) servers.
  - Intercepts requests/responses, extracts body/headers, and enqueues scan tasks to Redis.
  - Wait for results to block or allow traffic.
- **`consumer/`**: The scanning logic.
  - Pops tasks from the Redis queue.
  - Orchestrates the scanning process using the `Coordinator` and `ScannerService`.
  - Integrates with ClamAV via `clamd`.
- **`common/`**: Shared utilities and data access layers.
  - **`providers/`**: Pluggable data handling strategies (`DataProvider`).
    - `inline.py`: Small payloads stored directly in the queue/Redis.
    - `redis_stream.py`: Real-time streaming of data.
    - `shared_disk.py`: Large file handling using a shared PVC/volume.
  - `settings.py`: Shared configuration models using Pydantic.

## Key Design Patterns

- **Dependency Injection**: Used across all components via `dependency-injector` for better testability and modularity.
- **Provider Strategy**: The `DataProvider` abstraction (in `common/providers`) allows the scanner to handle different data transmission modes (disk, memory, stream) transparently.
- **Modular Scalability**: The Producer and Consumer are decoupled by Redis, allowing them to scale independently.
