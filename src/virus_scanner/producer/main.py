"""
Virus Scanner Producer (Envoy External Processor)

gRPC service that intercepts requests from Envoy, enqueues virus scan tasks to Redis,
and blocks malicious content.

Based on experiment/ncs-envoy-clamav/python/bridge.py
"""

import json
import logging
import os
import sys
import threading
from concurrent import futures
from http.server import BaseHTTPRequestHandler, HTTPServer

import grpc
import redis

from .containers import ProducerContainer
from .service import StreamScannerService

logger = logging.getLogger(__name__)

# Add current directory to path to find generated protos
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Envoy ext_proc proto imports
try:
    from envoy.service.ext_proc.v3 import (
        external_processor_pb2,
        external_processor_pb2_grpc,
    )
    from envoy.type.v3 import http_status_pb2
except ImportError as e:
    # Protos not generated yet
    logger.warning(f"Envoy protos not found or failed to import: {e}")
    external_processor_pb2 = None

    # Use a dummy class for inheritance if protos are missing to avoid crash at definition time
    class MockServicer:
        pass

    external_processor_pb2_grpc = type(
        "Mock", (), {"ExternalProcessorServicer": MockServicer}
    )
    http_status_pb2 = None


class HealthHandler(BaseHTTPRequestHandler):
    """HTTP handler for health checks and metrics"""

    def __init__(self, redis_client, *args, **kwargs):
        self.redis_client = redis_client
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()

            try:
                prio_len = self.redis_client.llen("scan_priority")
                norm_len = self.redis_client.llen("scan_normal")
                prio_tat_raw = self.redis_client.get("tat_priority_last")
                norm_tat_raw = self.redis_client.get("tat_normal_last")

                prio_tat = prio_tat_raw.decode("utf-8") if prio_tat_raw else "0"
                norm_tat = norm_tat_raw.decode("utf-8") if norm_tat_raw else "0"

                res = f"virusscan_priority_queue_length {prio_len}\n"
                res += f"virusscan_normal_queue_length {norm_len}\n"
                res += f"virusscan_priority_tat_ms {prio_tat}\n"
                res += f"virusscan_normal_tat_ms {norm_tat}\n"

                ingest_tat_raw = self.redis_client.get("ingest_ms_last")
                ingest_tat = ingest_tat_raw.decode("utf-8") if ingest_tat_raw else "0"
                res += f"virusscan_ingest_tat_ms {ingest_tat}\n"

                self.wfile.write(res.encode())
            except Exception as e:
                logger.error(f"Metrics error: {e}")
                self.send_response(500)
                self.end_headers()

        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress HTTP logs


class MetricsServer:
    """HTTP server for health checks and Prometheus metrics"""

    def __init__(self, redis_client: redis.Redis, port: int = 8080):
        self.redis_client = redis_client
        self.port = port

    def run(self):
        """Start HTTP server"""

        def handler(*args, **kwargs):
            return HealthHandler(self.redis_client, *args, **kwargs)

        try:
            httpd = HTTPServer(("0.0.0.0", self.port), handler)
            logger.info(f"Starting metrics server on :{self.port}...")
            httpd.serve_forever()
        except Exception as e:
            logger.error(f"Failed to start metrics server: {e}")


class ExternalProcessorServicer(external_processor_pb2_grpc.ExternalProcessorServicer):
    """Envoy External Processor implementation"""

    def __init__(self, scanner_service: StreamScannerService):
        self.scanner = scanner_service

    def Process(self, request_iterator, context):
        is_priority = False
        task_id = None
        provider = None

        # Accessing Enum values - flattened in Python but using full path for clarity/reliability if possible
        # CONTINUE = external_processor_pb2.CommonResponse.ResponseStatus.CONTINUE
        # But usually external_processor_pb2.CommonResponse.CONTINUE works
        try:
            CONTINUE_STATUS = (
                external_processor_pb2.CommonResponse.ResponseStatus.Value("CONTINUE")
            )
        except (AttributeError, KeyError, ValueError):
            CONTINUE_STATUS = (
                0  # Default to 0 based on proto definition if attribute access fails
            )

        for req in request_iterator:
            try:
                if req.HasField("request_headers"):
                    logger.info("Received request headers")
                    for header in req.request_headers.headers.headers:
                        # TODO: will be implemented fetch priority kubernetes pod environment variable
                        if (
                            header.key.lower() == "x-priority"
                            and header.value.lower() == "high"
                        ):
                            is_priority = True
                            break

                    yield external_processor_pb2.ProcessingResponse(
                        request_headers=external_processor_pb2.HeadersResponse(
                            response=external_processor_pb2.CommonResponse(
                                status=CONTINUE_STATUS
                            )
                        )
                    )

                elif req.HasField("request_body"):
                    body = req.request_body.body
                    logger.info(f"Received request body chunk, len: {len(body)}")

                    if not task_id:
                        task_id, provider = self.scanner.prepare_scan(
                            is_priority=is_priority
                        )
                        self.scanner.emit_task(task_id, is_priority=is_priority)

                    provider.push_chunk(body)

                    if req.request_body.end_of_stream:
                        provider.finalize_push()
                        self.scanner.record_ingest_time(task_id)

                        # 2. Wait for result (only on the last chunk)
                        status_raw = self.scanner.wait_for_result(task_id, timeout=30)

                        if not status_raw:
                            logger.error("Timeout waiting for scan result")
                            yield external_processor_pb2.ProcessingResponse(
                                request_body=external_processor_pb2.BodyResponse(
                                    response=external_processor_pb2.CommonResponse(
                                        status=CONTINUE_STATUS
                                    )
                                )
                            )
                        else:
                            status_json = status_raw.decode("utf-8")
                            status_data = json.loads(status_json)

                            if status_data.get("status") == "INFECTED":
                                msg = f"Virus detected! {status_data.get('virus', '')}"
                                yield external_processor_pb2.ProcessingResponse(
                                    immediate_response=external_processor_pb2.ImmediateResponse(
                                        status=http_status_pb2.HttpStatus(code=403),
                                        details=msg,
                                        body=msg.encode(),
                                    )
                                )
                            else:
                                yield external_processor_pb2.ProcessingResponse(
                                    request_body=external_processor_pb2.BodyResponse(
                                        response=external_processor_pb2.CommonResponse(
                                            status=CONTINUE_STATUS
                                        )
                                    )
                                )
                    else:
                        # Continue receiving chunks
                        yield external_processor_pb2.ProcessingResponse(
                            request_body=external_processor_pb2.BodyResponse(
                                response=external_processor_pb2.CommonResponse(
                                    status=CONTINUE_STATUS
                                )
                            )
                        )

                else:
                    # Other phases
                    yield external_processor_pb2.ProcessingResponse(
                        request_headers=external_processor_pb2.HeadersResponse(
                            response=external_processor_pb2.CommonResponse(
                                status=CONTINUE_STATUS
                            )
                        )
                    )
            except Exception as iteration_error:
                logger.exception(f"Error during Process iteration: {iteration_error}")
                # We can't yield anymore if it's a fatal error in generator logic,
                # but letting it raise allows gRPC to handle it.


class ProducerService:
    """Producer gRPC service"""

    def __init__(self, container: "ProducerContainer"):
        self.redis = container.redis_client()
        self.settings = container.settings()
        self.container = container
        self.server = None
        self.metrics_server = None

    def start(self):
        """Start gRPC server and metrics server"""
        if external_processor_pb2_grpc is None or external_processor_pb2 is None:
            raise RuntimeError(
                "Envoy protos not generated or failed to load. Run generate_protos.sh first."
            )

        # Start gRPC server
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        external_processor_pb2_grpc.add_ExternalProcessorServicer_to_server(
            ExternalProcessorServicer(self.container.scanner_service()), self.server
        )
        self.server.add_insecure_port("[::]:50051")
        logger.info("Starting Virus Scanner Producer (Envoy ext_proc) on port 50051...")
        self.server.start()

        # Start metrics server
        self.metrics_server = MetricsServer(self.redis, port=8080)
        metrics_thread = threading.Thread(target=self.metrics_server.run)
        metrics_thread.daemon = True
        metrics_thread.start()

        try:
            self.server.wait_for_termination()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop gRPC server"""
        if self.server:
            self.server.stop(0)


def serve():
    """Entry point for virus-scanner-producer command"""

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    container = ProducerContainer()
    container.config.from_dict(
        {
            "redis_host": os.environ.get("REDIS_HOST", "localhost"),
            "redis_port": int(os.environ.get("REDIS_PORT", "6379")),
            "scan_tmp_dir": os.environ.get("SCAN_TMP_DIR", "/tmp/virusscan"),
            "scan_file_threshold_mb": int(
                os.environ.get("SCAN_FILE_THRESHOLD_MB", "10")
            ),
        }
    )

    service = ProducerService(container=container)
    service.start()


if __name__ == "__main__":
    serve()
