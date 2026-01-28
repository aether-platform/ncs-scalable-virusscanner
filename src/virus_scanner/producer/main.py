"""
Virus Scanner Producer (Envoy External Processor)

gRPC service that intercepts requests from Envoy, enqueues virus scan tasks to Redis,
and blocks malicious content.

Based on experiment/ncs-envoy-clamav/python/bridge.py
"""
import grpc
from concurrent import futures
import time
import os
import redis
import uuid
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# Envoy ext_proc proto imports
try:
    from envoy.service.ext_proc.v3 import external_processor_pb2
    from envoy.service.ext_proc.v3 import external_processor_pb2_grpc
    from envoy.config.core.v3 import base_pb2
    from envoy.type.v3 import http_status_pb2
except ImportError:
    # Protos not generated yet
    external_processor_pb2 = None
    external_processor_pb2_grpc = None
    http_status_pb2 = None

from .settings import ProducerSettings

logger = logging.getLogger(__name__)


class HealthHandler(BaseHTTPRequestHandler):
    """HTTP handler for health checks and metrics"""
    
    def __init__(self, redis_client, *args, **kwargs):
        self.redis_client = redis_client
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
            try:
                prio_len = self.redis_client.llen("scan_priority")
                norm_len = self.redis_client.llen("scan_normal")
                prio_tat = self.redis_client.get("tat_priority_last") or "0"
                norm_tat = self.redis_client.get("tat_normal_last") or "0"
                
                res = f"virusscan_priority_queue_length {prio_len}\n"
                res += f"virusscan_normal_queue_length {norm_len}\n"
                res += f"virusscan_priority_tat_ms {prio_tat}\n"
                res += f"virusscan_normal_tat_ms {norm_tat}\n"
                
                self.wfile.write(res.encode())
            except Exception as e:
                logger.error(f"Metrics error: {e}")
                self.send_response(500)
                self.end_headers()
                
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
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
        handler = lambda *args, **kwargs: HealthHandler(self.redis_client, *args, **kwargs)
        httpd = HTTPServer(('0.0.0.0', self.port), handler)
        logger.info(f"Starting metrics server on :{self.port}...")
        httpd.serve_forever()


class ExternalProcessorServicer(external_processor_pb2_grpc.ExternalProcessorServicer):
    """Envoy External Processor implementation"""
    
    def __init__(self, redis_client: redis.Redis, settings: ProducerSettings):
        self.redis = redis_client
        self.settings = settings
    
    def Process(self, request_iterator, context):
        is_priority = False
        
        for req in request_iterator:
            if req.HasField('request_headers'):
                logger.info("Received request headers")
                for header in req.request_headers.headers.headers:
                    if header.key.lower() == 'x-priority' and header.value.lower() == 'high':
                        is_priority = True
                        break
                
                yield external_processor_pb2.ProcessingResponse(
                    request_headers=external_processor_pb2.HeadersResponse(
                        response=external_processor_pb2.CommonResponse(
                            status=external_processor_pb2.CommonResponse.Status.CONTINUE
                        )
                    )
                )
                
            elif req.HasField('request_body'):
                body = req.request_body.body
                logger.info(f"Received request body chunk, len: {len(body)}")
                
                task_id = str(uuid.uuid4())
                payload_mode = "BODY"
                payload_content = body.decode('latin1')  # Preserve raw bytes
                
                # Check for large files
                if len(body) > self.settings.scan_file_threshold_mb * 1024 * 1024:
                    if not os.path.exists(self.settings.scan_tmp_dir):
                        os.makedirs(self.settings.scan_tmp_dir)
                    file_path = os.path.join(self.settings.scan_tmp_dir, task_id)
                    with open(file_path, 'wb') as f:
                        f.write(body)
                    payload_mode = "PATH"
                    payload_content = file_path
                
                queue_name = "scan_priority" if is_priority else "scan_normal"
                now_ns = time.time_ns()
                
                # Task format: taskID|MODE|TIMESTAMP|CONTENT
                self.redis.lpush(queue_name, f"{task_id}|{payload_mode}|{now_ns}|{payload_content}")
                
                # Wait for result
                res = self.redis.brpop(f"result:{task_id}", timeout=30)
                
                if not res:
                    logger.error("Timeout waiting for scan result")
                    yield external_processor_pb2.ProcessingResponse(
                        request_body=external_processor_pb2.BodyResponse(
                            response=external_processor_pb2.CommonResponse(
                                status=external_processor_pb2.CommonResponse.Status.CONTINUE
                            )
                        )
                    )
                else:
                    _, status = res
                    if status == "INFECTED":
                        msg = "Virus detected!"
                        yield external_processor_pb2.ProcessingResponse(
                            immediate_response=external_processor_pb2.ImmediateResponse(
                                status=http_status_pb2.HttpStatus(code=403),
                                details=msg,
                                body=msg
                            )
                        )
                    else:
                        yield external_processor_pb2.ProcessingResponse(
                            request_body=external_processor_pb2.BodyResponse(
                                response=external_processor_pb2.CommonResponse(
                                    status=external_processor_pb2.CommonResponse.Status.CONTINUE
                                )
                            )
                        )

            else:
                # Other phases
                yield external_processor_pb2.ProcessingResponse(
                     request_headers=external_processor_pb2.HeadersResponse(
                        response=external_processor_pb2.CommonResponse(
                            status=external_processor_pb2.CommonResponse.Status.CONTINUE
                        )
                    )
                )


class ProducerService:
    """Producer gRPC service"""
    
    def __init__(self, redis_client: redis.Redis, settings: ProducerSettings):
        self.redis = redis_client
        self.settings = settings
        self.server = None
        self.metrics_server = None
    
    def start(self):
        """Start gRPC server and metrics server"""
        if external_processor_pb2_grpc is None:
            raise RuntimeError("Envoy protos not generated. Run generate_protos.sh first.")
        
        # Start gRPC server
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        external_processor_pb2_grpc.add_ExternalProcessorServicer_to_server(
            ExternalProcessorServicer(self.redis, self.settings), self.server
        )
        self.server.add_insecure_port('[::]:50051')
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
    from .containers import ProducerContainer
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    
    container = ProducerContainer()
    container.config.from_dict({
        "redis_host": os.environ.get("REDIS_HOST", "localhost"),
        "redis_port": int(os.environ.get("REDIS_PORT", "6379")),
        "scan_tmp_dir": os.environ.get("SCAN_TMP_DIR", "/tmp/virusscan"),
        "scan_file_threshold_mb": int(os.environ.get("SCAN_FILE_THRESHOLD_MB", "10"))
    })
    
    service = ProducerService(
        redis_client=container.redis_client(),
        settings=container.settings()
    )
    service.start()


if __name__ == '__main__':
    serve()
