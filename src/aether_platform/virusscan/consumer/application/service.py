import json
import logging
import time
from typing import Any, Callable

from dependency_injector.wiring import Provide, inject

from aether_platform.virusscan.common.queue.provider import QueueProvider
from aether_platform.virusscan.consumer.infrastructure.engine_client import (
    ScannerEngineClient,
)
from aether_platform.virusscan.consumer.settings import Settings


class ScannerTaskService:
    """
    Application service that processes individual virus scan tasks.
    Coordinates downloading the file, executing the scan, and reporting results.
    """

    def _get_free_memory_mb(self) -> float:
        """Internal helper to calculate available system memory in MB."""
        if not self.config.enable_memory_check:
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
        await self.provider.set(ack_key, b"1", ex=300)

    async def _report_result(self, stream_id: str, result_payload: dict):
        """Internal helper to persist scan results to the queue provider."""
        result_json = json.dumps(result_payload).encode("utf-8")
        result_key = f"result:{stream_id}"
        await self.provider.push(result_key, result_json)

    def _notify_console(self, tenant_id: str, virus_name: str, task_id: str):
        """Internal helper to notify the management console of an infection."""
        try:
            import os

            import requests

            console_url = os.environ.get(
                "CONSOLE_API_URL", "http://aether-console:3000"
            )
            requests.post(
                f"{console_url}/api/webhooks/virus-scan",
                json={
                    "tenant_id": tenant_id,
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
            is_virus, virus_name = await self.engine.scan(provider)
        except Exception as e:
            error_payload = {"status": "ERROR", "message": str(e)}
            await self._report_result(stream_id, error_payload)
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
        self.logger.info(
            f"Scan Done {stream_id} [{priority}]: {duration * 1000:.1f}ms, Virus={virus_name if is_virus else 'None'}, "
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
            },
        }
        await self._report_result(stream_id, result_payload)

        # 5. Record Metrics (Legacy StateStore for backward compatibility if needed)
        try:
            tat_key = f"tat_{priority}_last"
            await self.provider.set(
                tat_key, str(total_tat * 1000)
            )  # Store in ms for compatibility
        except Exception as e:
            self.logger.warning(f"Failed to record metrics in StateStore: {e}")

    @inject
    def __init__(
        self,
        queue_provider: QueueProvider = Provide["queue_provider"],
        settings: Settings = Provide["settings"],
        engine: ScannerEngineClient = Provide["engine"],
        provider_factory: Callable[..., Any] = Provide["data_provider"],
    ):
        """
        Initializes the task service.
        """
        self.provider = queue_provider
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

            await self._process_stream_task(
                stream_id, enqueued_at, queue_name, start_process_time
            )
        except json.JSONDecodeError:
            self.logger.error(
                f"Failed to decode task JSON (might be old format): {task_data}"
            )
        except Exception as e:
            self.logger.error(f"Failed to process task: {e}")
