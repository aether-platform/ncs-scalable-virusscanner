import hashlib
import traceback
from concurrent import futures

import grpc
from dependency_injector import providers
from dependency_injector.wiring import Provide, inject

# Envoy Protos
from envoy.service.ext_proc.v3 import external_processor_pb2 as ext_proc
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as ext_proc_grpc
from envoy.type.v3 import http_status_pb2

from ..core.containers import Container, FeatureFlagService, create_container
from .service import ScanProducerService


class ExternalProcessorController(ext_proc_grpc.ExternalProcessorServicer):
    @inject
    def __init__(
        self,
        service: ScanProducerService = Provide[Container.producer_service],
        feature_flags: FeatureFlagService = Provide[Container.feature_flags],
    ):
        self.service = service
        self.feature_flags = feature_flags

    def Process(self, request_iterator, context):
        print("[Producer] New gRPC stream opened.")
        is_priority = self.feature_flags.is_high_priority

        try:
            for request in request_iterator:
                if request.HasField("request_headers"):
                    print("[Producer] Handling headers...")
                    for header in request.request_headers.headers.headers:
                        if (
                            header.key.lower() == "x-priority"
                            and header.value.lower() == "high"
                        ):
                            is_priority = True

                    yield ext_proc.ProcessingResponse(
                        request_headers=ext_proc.HeadersResponse(
                            response=ext_proc.CommonResponse(
                                status=ext_proc.CommonResponse.CONTINUE
                            )
                        )
                    )

                elif request.HasField("request_body"):
                    body_bytes = request.request_body.body
                    file_hash = hashlib.sha256(body_bytes).hexdigest()
                    print(f"[Producer] Handling body, hash: {file_hash}")

                    # Check Cache
                    result = self.service.redis_meta.get(f"scan:{file_hash}")
                    if result:
                        print(f"[Producer] Cache HIT: {result}")
                    else:
                        print(f"[Producer] Cache MISS. Priority={is_priority}")
                        provider = self.service.prepare_scan(file_hash)
                        provider.push_chunk(body_bytes)
                        self.service.emit_task(file_hash, is_priority=is_priority)
                        result = self.service.wait_for_result(file_hash)

                        if not result:
                            print("[Producer] Timeout. Defaulting to CLEAN.")
                            result = "CLEAN"

                    yield self._build_body_response(result, file_hash)
                    break
        except grpc.RpcError:
            pass
        except Exception as e:
            print(f"[Producer] Stream error: {e}")
            traceback.print_exc()

    def _build_body_response(self, result, file_hash):
        if result == "INFECTED":
            return ext_proc.ProcessingResponse(
                immediate_response=ext_proc.ImmediateResponse(
                    status=http_status_pb2.HttpStatus(code=403),
                    details=f"Infected file ({file_hash})",
                    body=b"Access Denied: Malware detected.\n",
                )
            )
        else:
            return ext_proc.ProcessingResponse(
                request_body=ext_proc.BodyResponse(
                    response=ext_proc.CommonResponse(
                        status=ext_proc.CommonResponse.CONTINUE
                    )
                )
            )


def serve():
    container = create_container()

    # Wire Producer dependencies
    container.producer_service = providers.Singleton(
        ScanProducerService,
        redis_meta=container.redis_meta,
        provider_factory=container.data_provider_factory,
    )
    container.feature_flags = providers.Singleton(
        FeatureFlagService, provider=container.feature_provider
    )

    container.wire(modules=[__name__])

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=20))
    ext_proc_grpc.add_ExternalProcessorServicer_to_server(
        ExternalProcessorController(), server
    )
    server.add_insecure_port("[::]:50051")
    print("Scan Manager (Producer) starting on 50051...")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
