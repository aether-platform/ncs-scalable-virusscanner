import asyncio
import json
import logging
import time
from typing import Any, Callable

from dependency_injector.wiring import Provide, inject
from prometheus_client import Counter, Histogram

from aether_platform.virusscan.common.queue.provider import (
    QueueProvider, StateStoreProvider)
from aether_platform.virusscan.consumer.infrastructure.engine_client import \
    ScannerEngineClient
from aether_platform.virusscan.consumer.settings import Settings

# TAT計測用メトリクス
# stage: "wait" (キュー投入〜処理開始), "process" (処理時間), "total" (キュー投入〜完了)
TAT_HISTOGRAM = Histogram(
    "scanner_tat_seconds",
    "Time taken from enqueue to completion",
    ["priority", "stage"],
    buckets=[1, 5, 10, 30, 60, 120, 300, 600],
)

# サイズ統計
SCAN_SIZE_BYTES = Histogram(
    "scanner_scan_size_bytes",
    "Scanned content size in bytes",
    ["priority", "result"],
    buckets=[
        1024,                   # 1 KB
        10 * 1024,              # 10 KB
        100 * 1024,             # 100 KB
        1024 * 1024,            # 1 MB
        10 * 1024 * 1024,       # 10 MB
        100 * 1024 * 1024,      # 100 MB
        1024 * 1024 * 1024,     # 1 GB
        10 * 1024**3,           # 10 GB
        100 * 1024**3,          # 100 GB
    ],
)

SCAN_BYTES_TOTAL = Counter(
    "scanner_scan_bytes_total",
    "Total bytes scanned by ClamAV",
    ["priority"],
)

# サイズ別処理時間 — size_class ラベルで分類
SCAN_DURATION_BY_SIZE = Histogram(
    "scanner_scan_duration_by_size_seconds",
    "Scan processing time bucketed by content size class",
    ["priority", "size_class"],
    buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60, 120],
)

SCAN_RESULTS_TOTAL = Counter(
    "scanner_scan_results_total",
    "Scan results by outcome",
    ["priority", "result"],
)


def _size_class(nbytes: int) -> str:
    """Classify byte count into a human-readable size bucket label."""
    if nbytes < 1024:
        return "tiny_lt1k"
    if nbytes < 100 * 1024:
        return "small_1k_100k"
    if nbytes < 1024 * 1024:
        return "medium_100k_1m"
    if nbytes < 100 * 1024 * 1024:
        return "large_1m_100m"
    if nbytes < 1024 * 1024 * 1024:
        return "xlarge_100m_1g"
    if nbytes < 10 * 1024**3:
        return "huge_1g_10g"
    return "massive_gt10g"


class ScannerTaskService:
    """
    Application service that processes individual virus scan tasks.
    Coordinates downloading the file, executing the scan, and reporting results.
    """

    def _get_free_memory_mb(self) -> float:
        """Internal helper to calculate available system memory in MB."""
        if not self.settings.enable_memory_check:
            return float("inf")
        try:
            import psutil

            vm = psutil.virtual_memory()
            return vm.available / (1024 * 1024)
        except ImportError:
            return float("inf")

    async def _send_ack(self, stream_id: str):
        """Signals to the producer that the task has been accepted by a worker."""
        ack_key = f"ack:{stream_id}"
        await self.provider.push(ack_key, b"1")
        # Set a reasonable expiry for the ACK key just in case
        await self.store.set(ack_key, b"1", ex=300)

    async def _report_result(self, stream_id: str, result_payload: dict):
        """Internal helper to persist scan results to the queue provider."""
        result_json = json.dumps(result_payload).encode("utf-8")
        result_key = f"result:{stream_id}"
        await self.provider.push(result_key, result_json)

    async def _notify_console(
        self, tenant_id: str, virus_name: str, task_id: str, client_ip: str = "unknown"
    ):
        """Internal helper to notify the management console of an infection."""
        try:
            import os

            import httpx

            console_url = os.environ.get(
                "CONSOLE_API_URL", "http://aether-console:3000"
            )
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{console_url}/api/webhooks/virus-scan",
                    json={
                        "tenant_id": tenant_id,
                        "client_ip": client_ip,
                        "virus_name": virus_name,
                        "task_id": task_id,
                        "status": "INFECTED",
                    },
                    timeout=5,
                )
        except Exception as e:
            self.logger.error(f"Failed to notify console: {e}")

    async def _process_stream_task(
        self,
        stream_id: str,
        enqueued_at: float,
        queue_name: str,
        start_process_time: float,
        tenant_id: str = "unknown",
        client_ip: str = "unknown",
    ):
        """
        [Stage 2: Scanning Workflow]
        ワーカーがジョブを受け取った後の実際の処理フローです。

        Steps:
            1. ACK Handshake: プロデューサーへ受付完了（ACK）を通知し、Chunk送信を開始させます。
            2. Stream Monitor: Redis Streamからチャンクを順次拾い、ClamAVへ転送します（追いかけスキャン）。
            3. Finalize: 全チャンク走査後、結果を報告します。
        """
        # 1. ACK Handshake (Stage 1 の完了通知)
        await self._send_ack(stream_id)

        # 2. Data Monitoring & Scan Execution (Stage 2 ストリームスキャン)
        try:
            # We use RedisStreamProvider which is async
            provider = self.provider_factory("STREAM", chunks_key=stream_id)
        except Exception as e:
            self.logger.error(f"Failed to create STREAM provider for {stream_id}: {e}")
            return

        # 3. Execute Scan
        mem_before = self._get_free_memory_mb()
        start_scan_time = time.time()

        try:
            is_virus, virus_name, bytes_scanned = await self.engine.scan(provider)
        except Exception as e:
            error_payload = {"status": "ERROR", "message": str(e)}
            await self._report_result(stream_id, error_payload)
            SCAN_RESULTS_TOTAL.labels(
                priority="high" if "priority" in queue_name else "normal",
                result="error",
            ).inc()
            return

        end_time = time.time()
        duration = end_time - start_scan_time
        mem_after = self._get_free_memory_mb()
        mem_delta = mem_before - mem_after if mem_before != float("inf") else 0

        # TAT Calculations (seconds)
        wait_tat = start_process_time - enqueued_at
        process_tat = end_time - start_process_time
        total_tat = end_time - enqueued_at

        priority = "high" if "priority" in queue_name else "normal"
        result_label = "infected" if is_virus else "clean"
        sc = _size_class(bytes_scanned)

        # Record metrics to Prometheus
        TAT_HISTOGRAM.labels(priority=priority, stage="wait").observe(wait_tat)
        TAT_HISTOGRAM.labels(priority=priority, stage="process").observe(process_tat)
        TAT_HISTOGRAM.labels(priority=priority, stage="total").observe(total_tat)

        # Size & size-based duration metrics
        SCAN_SIZE_BYTES.labels(priority=priority, result=result_label).observe(bytes_scanned)
        SCAN_BYTES_TOTAL.labels(priority=priority).inc(bytes_scanned)
        SCAN_DURATION_BY_SIZE.labels(priority=priority, size_class=sc).observe(process_tat)
        SCAN_RESULTS_TOTAL.labels(priority=priority, result=result_label).inc()

        self.logger.info(
            f"Scan Done {stream_id} [{priority}]: {duration * 1000:.1f}ms, "
            f"Size={bytes_scanned} ({sc}), Virus={virus_name if is_virus else 'None'}, "
            f"TAT(wait/proc/total)={wait_tat:.1f}/{process_tat:.1f}/{total_tat:.1f}s, MemDelta={mem_delta:.0f}MB"
        )

        # 4. Report Results
        result_payload = {
            "status": "INFECTED" if is_virus else "CLEAN",
            "virus": virus_name if is_virus else None,
            "stream_id": stream_id,
            "metrics": {
                "scan_ms": duration * 1000,
                "wait_tat_s": wait_tat,
                "process_tat_s": process_tat,
                "total_tat_s": total_tat,
                "bytes_scanned": bytes_scanned,
                "size_class": sc,
            },
        }
        await self._report_result(stream_id, result_payload)

        # 4.5 Notify Console if infected (Async)
        if is_virus:
            # We don't await this directly if we want to proceed fast,
            # but in this context, it's safer to ensure it's sent or log it.
            # Using create_task to fire and forget if we don't want to wait.
            asyncio.create_task(
                self._notify_console(
                    tenant_id=tenant_id,
                    virus_name=virus_name,
                    task_id=stream_id,
                    client_ip=client_ip,
                )
            )

        # 5. Record Metrics (Legacy StateStore for backward compatibility if needed)
        try:
            tat_key = f"tat_{priority}_last"
            await self.store.set(
                tat_key, str(total_tat * 1000)
            )  # Store in ms for compatibility
        except Exception as e:
            self.logger.warning(f"Failed to record metrics in StateStore: {e}")

    @inject
    def __init__(
        self,
        queue_provider: QueueProvider = Provide["queue_provider"],
        state_store_provider: StateStoreProvider = Provide["state_store_provider"],
        settings: Settings = Provide["settings"],
        engine: ScannerEngineClient = Provide["engine"],
        provider_factory: Callable[..., Any] = Provide["data_provider"],
    ):
        """
        Initializes the task service.
        """
        self.provider = queue_provider
        self.store = state_store_provider
        self.settings = settings
        self.engine = engine
        self.provider_factory = provider_factory
        self.logger = logging.getLogger(__name__)

    async def process_task(
        self, task_data: str, queue_name: str, start_process_time: float
    ):
        """
        Orchestrates the lifecycle of a single scan task.
        Handles JSON job format: { "stream_id": "...", "enqueued_at": ..., ... }
        """
        try:
            job = json.loads(task_data)
            stream_id = job.get("stream_id")
            enqueued_at = job.get("enqueued_at", start_process_time)

            if not stream_id:
                self.logger.error(f"Job missing stream_id: {task_data}")
                return

            tenant_id = job.get("tenant_id", "unknown")
            client_ip = job.get("client_ip", "unknown")

            await self._process_stream_task(
                stream_id,
                enqueued_at,
                queue_name,
                start_process_time,
                tenant_id=tenant_id,
                client_ip=client_ip,
            )
        except json.JSONDecodeError:
            self.logger.error(
                f"Failed to decode task JSON (might be old format): {task_data}"
            )
        except Exception as e:
            self.logger.error(f"Failed to process task: {e}")
