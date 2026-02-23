import logging
from typing import Any, AsyncIterator

import grpc
from envoy.service.ext_proc.v3 import (external_processor_pb2,
                                       external_processor_pb2_grpc)
from envoy.type.v3 import http_status_pb2

from aether_platform.intelligent_cache.application.service import \
    IntelligentCacheService
from aether_platform.virusscan.producer.application.orchestrator import \
    ScanOrchestrator

logger = logging.getLogger(__name__)


class VirusScannerExtProcHandler(external_processor_pb2_grpc.ExternalProcessorServicer):
    """
    Async gRPC interface for Envoy external processing.
    """

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
        is_request_phase = True
        is_bypassed = False

        try:
            async for request in request_iterator:
                logger.debug(f"Received gRPC Request: {request.WhichOneof('request')}")

                # 1. Header Phase
                if request.HasField("request_headers") or request.HasField(
                    "response_headers"
                ):
                    if request.HasField("request_headers"):
                        headers = {
                            h.key.lower(): h.value
                            for h in request.request_headers.headers.headers
                        }
                        current_path = headers.get(":path", "unknown")
                        is_request_phase = True
                        logger.info(f"[HEADER] Request: {current_path}")
                    else:
                        headers = {
                            h.key.lower(): h.value
                            for h in request.response_headers.headers.headers
                        }
                        is_request_phase = False
                        logger.info("[HEADER] Response")

                    # Check Intelligent Cache / Bypass (Async)
                    logger.debug("Checking cache...")
                    if await self.cache.check_cache(current_path):
                        logger.info(f"CACHE HIT: {current_path}")
                        is_bypassed = True
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
                        is_bypassed = True
                    else:
                        logger.info(f"SCAN ACCEPTED: {task_id}")

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
                    logger.debug(
                        f"Pushing chunk for {task_id} ({len(body_field.body)} bytes)"
                    )
                    await provider.push_chunk(body_field.body)

                    if body_field.end_of_stream:
                        logger.info(f"Finalizing Stream: {task_id}")
                        await provider.finalize_push()
                        await self.orchestrator.finalize_ingest(task_id)

                        logger.info(f"Waiting for Result: {task_id}")
                        result = await self.orchestrator.get_result(task_id)

                        if result.is_infected():
                            logger.error(f"BLOCKED: {result.virus_name}")
                            yield external_processor_pb2.ProcessingResponse(
                                immediate_response=external_processor_pb2.ImmediateResponse(
                                    status=http_status_pb2.HttpStatus(
                                        code=http_status_pb2.Forbidden
                                    ),
                                    details=f"Infected: {result.virus_name}",
                                    body=f"Virus Detected: {result.virus_name}",
                                )
                            )
                            return

                        logger.info(f"CLEAN: {task_id}")
                        await self.cache.store_cache(current_path)
                        yield self._continue_response(is_request_phase, phase="body")
                    else:
                        yield self._continue_response(is_request_phase, phase="body")

                else:
                    logger.debug("Unknown/Unsupported phase")
                    yield external_processor_pb2.ProcessingResponse()

        except Exception as e:
            logger.exception(f"CRITICAL ERROR in Process Stream: {e}")
            raise
