import asyncio
import importlib
import logging
import os
import sys

import grpc.aio as grpc
from dependency_injector.wiring import Provide

# 1. First, import core google protobuf descriptors to populate descriptor pool
from google.protobuf import descriptor_pb2  # noqa: F401
from prometheus_client import start_http_server


# --- Support for Envoy Protos ---
def load_all_pb2():
    # 1. First, import core google protobuf descriptors
    from google.protobuf import (  # noqa: F401
        any_pb2,
        duration_pb2,
        struct_pb2,
        timestamp_pb2,
        wrappers_pb2,
    )

    # Add the local producer path to sys.path so 'envoy', 'udpa', etc. can be imported
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    packages = ["udpa", "xds", "envoy", "validate"]
    modules_to_load = []

    for pkg_name in packages:
        pkg_dir = os.path.join(base_dir, pkg_name)
        if not os.path.exists(pkg_dir):
            continue

        # Manually walk to find all _pb2.py files
        for root, _, files in os.walk(pkg_dir):
            for file in files:
                if file.endswith("_pb2.py"):
                    rel_path = os.path.relpath(os.path.join(root, file), base_dir)
                    mod_name = rel_path.replace(os.sep, ".").replace(".py", "")
                    modules_to_load.append(mod_name)

    # Try multiple passes to handle dependencies
    loaded_set = set()
    for _ in range(5):
        pass_count = 0
        for mod_name in sorted(modules_to_load):
            if mod_name in loaded_set:
                continue
            try:
                importlib.import_module(mod_name)
                loaded_set.add(mod_name)
                pass_count += 1
            except Exception:
                pass
        if pass_count == 0:
            break


load_all_pb2()
# -----------------------------
# -----------------------------

from envoy.service.ext_proc.v3 import external_processor_pb2_grpc

from aether_platform.virusscan.producer.containers import ProducerContainer
from aether_platform.virusscan.producer.interfaces.grpc.handler import (
    VirusScannerExtProcHandler,
)
from aether_platform.virusscan.producer.interfaces.grpc.sds import (
    SecretDiscoveryHandler,
)

logger = logging.getLogger(__name__)


async def serve(
    handler: VirusScannerExtProcHandler = Provide[ProducerContainer.grpc_handler],
    sds_handler: SecretDiscoveryHandler = Provide[ProducerContainer.sds_handler],
    grpc_port: int = Provide[ProducerContainer.settings.provided.grpc_port],
):
    """Starts the VirusScanner Producer (Async gRPC + Prometheus metrics)."""
    # Start Prometheus metrics HTTP server on port 8080
    metrics_port = 8080
    start_http_server(metrics_port)
    logger.info(f"Prometheus metrics server started on port {metrics_port}")

    server = grpc.server()
    external_processor_pb2_grpc.add_ExternalProcessorServicer_to_server(handler, server)
    from envoy.service.secret.v3 import sds_pb2_grpc

    sds_pb2_grpc.add_SecretDiscoveryServiceServicer_to_server(sds_handler, server)

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
