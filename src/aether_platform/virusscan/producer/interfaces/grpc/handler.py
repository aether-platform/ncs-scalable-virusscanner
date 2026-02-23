import logging
import time
from typing import Any, AsyncIterator

import grpc
from envoy.service.ext_proc.v3 import (external_processor_pb2,
                                       external_processor_pb2_grpc)

from aether_platform.intelligent_cache.application.service import \
    IntelligentCacheService
from aether_platform.virusscan.producer.application.orchestrator import \
    ScanOrchestrator
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
        flagsmith_client: Any = None,
    ):
        self.orchestrator = orchestrator
        self.cache = cache
        self.settings = settings
        self.flagsmith = flagsmith_client

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
        if not self.flagsmith:
            return False

        try:
            logger.info(f"Querying Flagsmith for {tenant_id}")
            # Flagsmith query
            identity_flags = self.flagsmith.get_identity_flags(identifier=tenant_id)
            plan = identity_flags.get_feature_value("scan_plan")
            res = await self.cache.check_priority(plan) == "high"
            logger.info(f"Flagsmith result for {tenant_id}: {res}")
            return res
        except Exception as e:
            logger.warning(
                f"Flagsmith query failed for {tenant_id}, defaulting to normal: {e}"
            )
            return False

    async def Process(
        self,
        request_iterator: AsyncIterator[external_processor_pb2.ProcessingRequest],
        context: grpc.ServicerContext,
    ) -> AsyncIterator[external_processor_pb2.ProcessingResponse]:
        """
        Main async gRPC streaming method.
        """
        task_id = None
        provider = None
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
                    logger.debug("Checking priority...")
                    is_priority = await self._get_tenant_plan_priority(tenant_id)

                    # Stage 1: Handshake
                    logger.debug("Preparing session...")
                    task_id, provider = self.orchestrator.prepare_session(
                        is_priority, tenant_id
                    )
                    logger.info(f"Session Prepared: {task_id}")

                    logger.debug("Starting scan (handshake)...")
                    is_accepted = await self.orchestrator.start_scan(
                        task_id, is_priority, tenant_id
                    )

                    if not is_accepted:
                        logger.warning(f"SCAN BYPASSED: {task_id}")
                        SCAN_SESSIONS.labels(result="bypassed_congestion").inc()
                        is_bypassed = True
                    else:
                        logger.info(f"SCAN ACCEPTED: {task_id}")
                        SCAN_SESSIONS.labels(result="accepted").inc()

                    logger.debug("Yielding header response...")
                    yield self._continue_response(is_request_phase, phase="headers")

                # 2. Body Phase
                elif request.HasField("request_body") or request.HasField(
                    "response_body"
                ):
                    logger.debug(f"[BODY] Phase (is_bypassed={is_bypassed})")
                    if is_bypassed:
                        yield self._continue_response(is_request_phase, phase="body")
                        continue

                    body_field = (
                        request.request_body
                        if request.HasField("request_body")
                        else request.response_body
                    )

                    if not provider:
                        logger.warning("No provider for body chunk")
                        yield self._continue_response(is_request_phase, phase="body")
                        continue

                    # Provider push
                    chunk_len = len(body_field.body)
                    body_total_bytes += chunk_len
                    logger.debug(
                        f"Pushing chunk for {task_id} ({chunk_len} bytes)"
                    )
                    await provider.push_chunk(body_field.body)

                    if body_field.end_of_stream:
                        logger.info(f"Finalizing Stream: {task_id}")
                        await provider.finalize_push()
                        await self.orchestrator.finalize_ingest(task_id)

                        logger.info(f"Waiting for Result: {task_id}")
                        result = await self.orchestrator.get_result(task_id)

                        # Record size metrics
                        BODY_SIZE_BYTES.labels(method=current_method).observe(body_total_bytes)
                        BODY_BYTES_TOTAL.labels(method=current_method).inc(body_total_bytes)

                        REQUEST_DURATION.labels(method=current_method).observe(
                            time.monotonic() - request_start
                        )

                        if result.is_infected():
                            # Reset connection. Webhook notification handled by consumer.
                            logger.error(
                                f"INFECTED: {result.virus_name} "
                                f"[{current_method} {current_path}] — connection reset"
                            )
                            SCAN_SESSIONS.labels(result="infected").inc()
                            REQUESTS_TOTAL.labels(method=current_method, result="infected").inc()
                            await context.abort(
                                grpc.StatusCode.ABORTED,
                                f"Virus detected: {result.virus_name}",
                            )
                            return

                        logger.info(f"CLEAN: {task_id}")
                        SCAN_SESSIONS.labels(result="clean").inc()
                        REQUESTS_TOTAL.labels(method=current_method, result="clean").inc()
                        if current_method in self._CACHEABLE_METHODS:
                            await self.cache.store_cache(current_path)
                            CACHE_OPS.labels(operation="store").inc()
                        yield self._continue_response(is_request_phase, phase="body")
                    else:
                        yield self._continue_response(is_request_phase, phase="body")

                else:
                    logger.debug("Unknown/Unsupported phase")
                    yield external_processor_pb2.ProcessingResponse()

        except Exception as e:
            REQUESTS_TOTAL.labels(method=current_method, result="error").inc()
            SCAN_SESSIONS.labels(result="error").inc()
            logger.exception(f"CRITICAL ERROR in Process Stream: {e}")
            raise
        finally:
            ACTIVE_SESSIONS.dec()
