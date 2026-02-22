import json
import logging
import time
import uuid
from typing import Any, Dict, Tuple

from dependency_injector import providers
from dependency_injector.wiring import Provide, inject

from aether_platform.virusscan.producer.containers import ProducerContainer
from aether_platform.virusscan.producer.domain.models import ScanResult, ScanStatus
from aether_platform.virusscan.producer.infrastructure.redis_adapter import (
    RedisScanAdapter,
)

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Application service that orchestrates the workflow of a single virus scan.
    Now fully asynchronous.
    """

    _start_times: Dict[str, Tuple[int, str]] = {}

    @inject
    def __init__(
        self,
        redis_adapter: RedisScanAdapter = Provide[ProducerContainer.redis_adapter],
        provider_factory: providers.FactoryAggregate = Provide[
            ProducerContainer.data_provider
        ],
    ):
        """
        Initializes the orchestrator.
        """
        self.adapter = redis_adapter
        self.provider_factory = provider_factory
        self._start_times = {}  # task_id -> (start_ns, tenant_id)

    def _get_start_data(self, task_id: str) -> Tuple[int, str] | None:
        """Internal helper to retrieve session start data."""
        return self._start_times.get(task_id)

    def prepare_session(
        self, is_priority: bool = False, tenant_id: str = "unknown"
    ) -> Tuple[str, Any]:
        """
        Initializes a new scan session with a unique stream ID.
        """
        task_id = str(uuid.uuid4())
        self._start_times[task_id] = (time.time_ns(), tenant_id)

        # STREAM provider uses RedisStreamProvider which now has async methods
        provider = self.provider_factory("STREAM", chunks_key=task_id)
        return task_id, provider

    async def start_scan(
        self, task_id: str, is_priority: bool = False, tenant_id: str = "unknown"
    ) -> bool:
        """
        [Stage 1: Handshake]
        スキャンの開始を要求し、コンシューマーが受付可能か確認（ハンドシェイク）します。

        Steps:
            1. Predictive Bypass: 過去のTATに基づき、混雑状況を事前チェック。
            2. Enqueue Job: 軽量なメタデータを共通キューに投入。
            3. Wait for ACK: 特定のワーカーがこのIDを拾う（Handshake成立）のを待つ。
        """
        # 1. Predictive Congestion Bypass (事前混雑回避)
        last_tat = await self.adapter.get_last_tat(is_priority)
        if last_tat > 300.0:
            logger.warning(
                f"CONGESTION BYPASS (Predictive): {task_id} skipped. Last TAT: {last_tat:.1f}s"
            )
            return False

        # 2. Dispatch Metadata (メタデータ投入)
        data = self._get_start_data(task_id)
        start_time = data[0] if data else time.time_ns()
        await self.adapter.enqueue_task(
            task_id, "STREAM", start_time, tenant_id, is_priority
        )

        # 3. Handshake Execution (ハンドシェイク待機)
        # 300秒の待機。ワーカーがジョブを拾うと、Redisの 'ack:{id}' に1が書き込まれます。
        is_accepted = await self.adapter.wait_for_ack(task_id, timeout=300)
        if not is_accepted:
            logger.warning(
                f"HANDSHAKE FAILED (Timeout): {task_id} was not picked up within 300s."
            )
            return False

        return True

    async def finalize_ingest(self, task_id: str):
        """
        Records the completion of the data ingestion phase asynchronously.
        """
        data = self._get_start_data(task_id)
        if data:
            start_time, _ = data
            duration_ms = (time.time_ns() - start_time) / 1e6
            await self.adapter.record_metrics(task_id, duration_ms)

    async def get_result(self, task_id: str, timeout: int = 30) -> ScanResult:
        """
        Waits asynchronously and retrieves the scan result.
        """
        try:
            raw_res = await self.adapter.wait_for_result(task_id, timeout)
            self._start_times.pop(task_id, None)

            if not raw_res:
                return ScanResult(
                    task_id=task_id, status=ScanStatus.ERROR, detail="Timeout"
                )

            data = json.loads(raw_res.decode("utf-8"))
            status_str = data.get("status", "ERROR")

            return ScanResult(
                task_id=task_id,
                status=ScanStatus[status_str]
                if status_str in ScanStatus.__members__
                else ScanStatus.ERROR,
                virus_name=data.get("virus"),
                detail=data.get("detail"),
            )
        except Exception as e:
            self._start_times.pop(task_id, None)
            return ScanResult(task_id=task_id, status=ScanStatus.ERROR, detail=str(e))
