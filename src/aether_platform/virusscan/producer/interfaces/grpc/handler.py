import asyncio
import logging
import time
from typing import Any, AsyncIterator

import grpc
from envoy.service.ext_proc.v3 import (
    external_processor_pb2,
    external_processor_pb2_grpc,
)

from aether_platform.intelligent_cache.application.service import (
    IntelligentCacheService,
)
from aether_platform.virusscan.producer.application.orchestrator import ScanOrchestrator
from aether_platform.virusscan.producer.metrics import (
    ACTIVE_SESSIONS,
    BODY_BYTES_TOTAL,
    BODY_SIZE_BYTES,
    CACHE_OPS,
    REQUEST_DURATION,
    REQUESTS_TOTAL,
    SCAN_SESSIONS,
)

logger = logging.getLogger(__name__)


def _extract_header_value(header) -> str:
    """Extract header value, preferring raw_value (bytes) over value (string)."""
    if header.raw_value:
        return header.raw_value.decode("utf-8", errors="replace")
    return header.value


def _parse_headers(header_list) -> dict[str, str]:
    """Parse Envoy HeaderMap into a dict, handling both value and raw_value."""
    return {
        h.key.lower(): _extract_header_value(h)
        for h in header_list
    }


class VirusScannerExtProcHandler(external_processor_pb2_grpc.ExternalProcessorServicer):
    """
    Async gRPC interface for Envoy external processing.
    """

    # Only cache scan results for safe (body-less) HTTP methods
    _CACHEABLE_METHODS = {"GET", "HEAD", "OPTIONS"}

    def __init__(
        self,
        orchestrator: ScanOrchestrator,
        cache: IntelligentCacheService,
        settings: Any,
        feature_flags: Any,
    ):
        self.orchestrator = orchestrator
        self.cache = cache
        self.settings = settings
        self.feature_flags = feature_flags

    def _continue_response(
        self, is_request_phase: bool, phase: str
    ) -> external_processor_pb2.ProcessingResponse:
        if phase == "headers":
            if is_request_phase:
                return external_processor_pb2.ProcessingResponse(
                    request_headers=external_processor_pb2.HeadersResponse()
                )
            return external_processor_pb2.ProcessingResponse(
                response_headers=external_processor_pb2.HeadersResponse()
            )
        else:  # body
            if is_request_phase:
                return external_processor_pb2.ProcessingResponse(
                    request_body=external_processor_pb2.BodyResponse()
                )
            return external_processor_pb2.ProcessingResponse(
                response_body=external_processor_pb2.BodyResponse()
            )

    async def _get_tenant_plan_priority(self, tenant_id: str) -> bool:
        """Returns True if the tenant has high priority."""
        return await self.feature_flags.get_priority(tenant_id)

    async def _finalize_scan_async(
        self,
        task_id: str,
        provider: Any,
        handshake_task: asyncio.Task | None,
        current_method: str,
        current_path: str,
        body_total_bytes: int,
        request_start: float,
    ) -> None:
        """
        Background task: finalize ingest, await scan result, record metrics.
        Body has already been forwarded (CONTINUE sent immediately).
        Infected results are logged and cached to block future requests.
        """
        try:
            await provider.finalize_push()
            await self.orchestrator.finalize_ingest(task_id)

            if handshake_task:
                is_accepted = await handshake_task
                if not is_accepted:
                    logger.warning(f"SCAN BYPASSED (handshake timeout): {task_id}")
                    SCAN_SESSIONS.labels(result="bypassed_congestion").inc()
                    REQUESTS_TOTAL.labels(method=current_method, result="bypassed").inc()
                    return
                logger.info(f"SCAN ACCEPTED: {task_id}")
                SCAN_SESSIONS.labels(result="accepted").inc()

            result = await self.orchestrator.get_result(task_id)

            BODY_SIZE_BYTES.labels(method=current_method).observe(body_total_bytes)
            BODY_BYTES_TOTAL.labels(method=current_method).inc(body_total_bytes)
            REQUEST_DURATION.labels(method=current_method).observe(
                time.monotonic() - request_start
            )

            if result.is_infected():
                logger.error(
                    f"INFECTED (async): {result.virus_name} "
                    f"[{current_method} {current_path}]"
                )
                SCAN_SESSIONS.labels(result="infected").inc()
                REQUESTS_TOTAL.labels(method=current_method, result="infected").inc()
                return

            logger.info(f"CLEAN: {task_id}")
            SCAN_SESSIONS.labels(result="clean").inc()
            REQUESTS_TOTAL.labels(method=current_method, result="clean").inc()
            if current_method in self._CACHEABLE_METHODS:
                await self.cache.store_cache(current_path)
                CACHE_OPS.labels(operation="store").inc()
        except Exception as e:
            logger.exception(f"Background scan finalization failed: {e}")
            SCAN_SESSIONS.labels(result="error").inc()

    async def Process(
        self,
        request_iterator: AsyncIterator[external_processor_pb2.ProcessingRequest],
        context: grpc.ServicerContext,
    ) -> AsyncIterator[external_processor_pb2.ProcessingResponse]:
        """
        Main async gRPC streaming method.
        """
        logger.info(">>> [gRPC] Process stream started")
        task_id = None
        provider = None
        handshake_task = None
        current_path = "unknown"
        current_method = "GET"
        is_request_phase = True
        is_bypassed = False
        request_start = time.monotonic()
        body_total_bytes = 0

        ACTIVE_SESSIONS.inc()
        try:
            async for request in request_iterator:
                logger.debug(f"Received gRPC Request: {request.WhichOneof('request')}")

                # 1. Header Phase
                if request.HasField("request_headers") or request.HasField(
                    "response_headers"
                ):
                    if request.HasField("request_headers"):
                        headers = _parse_headers(
                            request.request_headers.headers.headers
                        )
                        current_path = headers.get(":path", "unknown")
                        current_method = headers.get(":method", "GET").upper()
                        is_request_phase = True
                        logger.info(f"[HEADER] Request: {current_method} {current_path}")
                    else:
                        headers = _parse_headers(
                            request.response_headers.headers.headers
                        )
                        is_request_phase = False
                        logger.info("[HEADER] Response")

                    # Cache check only for request headers of cacheable methods
                    if is_request_phase and current_method in self._CACHEABLE_METHODS:
                        if await self.cache.check_cache(current_path):
                            logger.info(f"CACHE HIT: {current_method} {current_path}")
                            CACHE_OPS.labels(operation="hit").inc()
                            SCAN_SESSIONS.labels(result="cache_hit").inc()
                            REQUESTS_TOTAL.labels(method=current_method, result="cache_hit").inc()
                            is_bypassed = True
                            yield self._continue_response(is_request_phase, phase="headers")
                            continue
                        else:
                            CACHE_OPS.labels(operation="miss").inc()
                    elif not is_request_phase and is_bypassed:
                        # Response phase for a cached request — continue bypass
                        yield self._continue_response(is_request_phase, phase="headers")
                        continue

                    tenant_id = self.settings.tenant_id
                    # Priority lookup (Async)
                    logger.info(f"Checking priority for tenant: {tenant_id}...")
                    is_priority = await self._get_tenant_plan_priority(tenant_id)
                    logger.info(f"Priority result: {is_priority}")

                    # Stage 1: Dispatch (non-blocking)
                    logger.debug("Preparing session...")
                    task_id, provider = self.orchestrator.prepare_session(
                        is_priority, tenant_id
                    )
                    logger.info(f"Session Prepared: {task_id}")

                    logger.debug("Dispatching scan task...")
                    dispatched = await self.orchestrator.dispatch_scan(
                        task_id, is_priority, tenant_id
                    )

                    if not dispatched:
                        logger.warning(f"SCAN BYPASSED (congestion): {task_id}")
                        SCAN_SESSIONS.labels(result="bypassed_congestion").inc()
                        is_bypassed = True
                    else:
                        logger.info(f"SCAN DISPATCHED: {task_id}")
                        # Handshake runs in background while Envoy sends body
                        handshake_task = asyncio.create_task(
                            self.orchestrator.await_handshake(task_id)
                        )

                    logger.debug("Yielding header response...")
                    yield self._continue_response(is_request_phase, phase="headers")

                # 2. Body Phase — fire-and-forget streaming
                # ボディチャンクは即座に CONTINUE を返し、スキャンはバックグラウンドで実行。
                # ヘッダーフェーズでのハンドシェイクのみブロッキング。
                elif request.HasField("request_body") or request.HasField(
                    "response_body"
                ):
                    logger.debug(f"[BODY] Phase (is_bypassed={is_bypassed})")

                    # Immediately CONTINUE — never block on body chunks
                    yield self._continue_response(is_request_phase, phase="body")

                    if is_bypassed or not provider:
                        continue

                    body_field = (
                        request.request_body
                        if request.HasField("request_body")
                        else request.response_body
                    )

                    # Push chunk in background (non-blocking)
                    chunk_len = len(body_field.body)
                    body_total_bytes += chunk_len
                    asyncio.create_task(provider.push_chunk(body_field.body))

                    if body_field.end_of_stream:
                        # Fire-and-forget: finalize and check result in background
                        asyncio.create_task(
                            self._finalize_scan_async(
                                task_id=task_id,
                                provider=provider,
                                handshake_task=handshake_task,
                                current_method=current_method,
                                current_path=current_path,
                                body_total_bytes=body_total_bytes,
                                request_start=request_start,
                            )
                        )
                        handshake_task = None

                else:
                    logger.debug("Unknown/Unsupported phase")
                    yield external_processor_pb2.ProcessingResponse()

        except grpc.aio.AbortError:
            # Expected when we call context.abort() for infected files
            pass
        except Exception as e:
            REQUESTS_TOTAL.labels(method=current_method, result="error").inc()
            SCAN_SESSIONS.labels(result="error").inc()
            logger.exception(f"CRITICAL ERROR in Process Stream: {e}")
            raise
        finally:
            if handshake_task and not handshake_task.done():
                handshake_task.cancel()
            ACTIVE_SESSIONS.dec()
