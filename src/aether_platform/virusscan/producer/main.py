import logging
from concurrent import futures

import grpc
from dependency_injector.wiring import Provide, inject
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc

from aether_platform.virusscan.producer.containers import ProducerContainer
from aether_platform.virusscan.producer.interfaces.grpc.handler import (
    VirusScannerExtProcHandler,
)

logger = logging.getLogger(__name__)


@inject
def serve(
    handler: VirusScannerExtProcHandler = Provide[ProducerContainer.grpc_handler],
    grpc_port: int = Provide[ProducerContainer.settings.provided.grpc_port],
):
    """Starts the VirusScanner Producer."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    external_processor_pb2_grpc.add_ExternalProcessorServicer_to_server(handler, server)

    server.add_insecure_port(f"[::]:{grpc_port}")
    logger.info(
        f"Starting Advanced VirusScanner Producer (gRPC) on port {grpc_port}..."
    )
    server.start()
    server.wait_for_termination()


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    container = ProducerContainer()
    container.wire(modules=[__name__])

    serve()


if __name__ == "__main__":
    main()
