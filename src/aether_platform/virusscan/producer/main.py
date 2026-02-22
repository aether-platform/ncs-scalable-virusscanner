import asyncio
import logging

import grpc.aio as grpc
from dependency_injector.wiring import Provide, inject
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc

from aether_platform.virusscan.producer.containers import ProducerContainer
from aether_platform.virusscan.producer.interfaces.grpc.handler import \
    VirusScannerExtProcHandler

logger = logging.getLogger(__name__)


@inject
async def serve(
    handler: VirusScannerExtProcHandler = Provide[ProducerContainer.grpc_handler],
    grpc_port: int = Provide[ProducerContainer.settings.provided.grpc_port],
):
    """Starts the VirusScanner Producer (Async gRPC)."""
    server = grpc.server()
    external_processor_pb2_grpc.add_ExternalProcessorServicer_to_server(handler, server)

    server.add_insecure_port(f"[::]:{grpc_port}")
    logger.info(
        f"Starting Advanced VirusScanner Producer (Async gRPC) on port {grpc_port}..."
    )
    await server.start()
    await server.wait_for_termination()


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    container = ProducerContainer()
    container.wire(modules=[__name__])

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
