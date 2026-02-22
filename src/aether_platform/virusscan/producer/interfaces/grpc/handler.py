import logging
from typing import Any, Iterator

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
    gRPC interface that translates Envoy external processing requests into
    domain/application layer actions (Virus Scanning).
    """

    def __init__(
        self,
        orchestrator: ScanOrchestrator,
        cache: IntelligentCacheService,
        flagsmith_client: Any = None,
    ):
        """
        Initializes the gRPC handler.

        Args:
            orchestrator: The application orchestrator for scanning sessions.
            cache: The intelligent cache service for policy and bypass.
            flagsmith_client: Optional Flagsmith client for feature flagging.
        """
        self.orchestrator = orchestrator
        self.cache = cache
        self.flagsmith = flagsmith_client

    def _continue_response(
        self, is_request_phase: bool, phase: str
    ) -> external_processor_pb2.ProcessingResponse:
        """Internal helper to create standard continuation responses."""
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

    def _get_tenant_plan_priority(self, tenant_id: str) -> bool:
        """Internal helper to retrieve the priority status for a tenant via Flagsmith."""
        if not self.flagsmith:
            return False

        try:
            # Query Flagsmith identity for the scan_plan feature
            identity_flags = self.flagsmith.get_identity_flags(identifier=tenant_id)
            plan = identity_flags.get_feature_value("scan_plan")
            return self.cache.check_priority(plan) == "high"
        except Exception as e:
            logger.warning(
                f"Flagsmith query failed for {tenant_id}, defaulting to normal: {e}"
            )
            return False

    def Process(
        self,
        request_iterator: Iterator[external_processor_pb2.ProcessingRequest],
        context: grpc.ServicerContext,
    ) -> Iterator[external_processor_pb2.ProcessingResponse]:
        """
        Main gRPC streaming method that handles Envoy processing requests.
        """
        # Context for the current HTTP stream
        task_id = None
        provider = None
        current_path = "unknown"
        is_request_phase = True
        is_bypassed = False

        for request in request_iterator:
            # 1. Header Phase: Bypass and Initialization
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
                else:
                    headers = {
                        h.key.lower(): h.value
                        for h in request.response_headers.headers.headers
                    }
                    is_request_phase = False

                # Check Intelligent Cache / Bypass
                if self.cache.check_cache(current_path):
                    logger.info(f"CACHE HIT: {current_path}")
                    is_bypassed = True
                    yield self._continue_response(is_request_phase, phase="headers")
                    continue

                # Prepare session
                tenant_id = (
                    headers.get("x-aether-tenant")
                    or headers.get("x-forwarded-for")
                    or "unknown"
                )

                # Priority lookup via Flagsmith
                is_priority = self._get_tenant_plan_priority(tenant_id)

                # Notable domain metrics tracking
                notable_type = self.cache.get_notable_type(current_path)
                if notable_type:
                    logger.info(
                        f"NOTABLE ACCESS: {current_path} (Type: {notable_type})"
                    )

                task_id, provider = self.orchestrator.prepare_session(
                    is_priority, tenant_id
                )
                self.orchestrator.start_scan(task_id, is_priority, tenant_id)

                yield self._continue_response(is_request_phase, phase="headers")

            # 2. Body Phase: Streaming Data
            elif request.HasField("request_body") or request.HasField("response_body"):
                if is_bypassed:
                    yield self._continue_response(is_request_phase, phase="body")
                    continue

                body_field = (
                    request.request_body
                    if request.HasField("request_body")
                    else request.response_body
                )
                if not provider:
                    yield self._continue_response(is_request_phase, phase="body")
                    continue

                provider.push_chunk(body_field.body)

                if body_field.end_of_stream:
                    # Final chunk: Await orchestration result
                    provider.finalize_push()
                    self.orchestrator.finalize_ingest(task_id)

                    result = self.orchestrator.get_result(task_id)

                    if result.is_infected():
                        logger.error(f"BLOCKED: Infected by {result.virus_name}")
                        yield external_processor_pb2.ProcessingResponse(
                            immediate_response=external_processor_pb2.ImmediateResponse(
                                status=http_status_pb2.HttpStatus(
                                    code=http_status_pb2.NotAcceptable
                                ),
                                details=f"Infected with {result.virus_name}",
                                body=f"Virus Detected: {result.virus_name}",
                            )
                        )
                        return

                    # Clean: Persist to Cache and Continue
                    self.cache.store_cache(current_path)
                    yield self._continue_response(is_request_phase, phase="body")
                else:
                    # Intermediate: Acknowledge immediately
                    yield self._continue_response(is_request_phase, phase="body")

            else:
                yield external_processor_pb2.ProcessingResponse()
