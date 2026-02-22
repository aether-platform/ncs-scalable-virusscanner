import asyncio
import logging
import os
import sys
import time

import uvicorn
from dependency_injector.wiring import Provide, inject
from litestar import Litestar
from litestar.plugins.prometheus import PrometheusConfig, PrometheusPlugin

from .containers import Container
from .interfaces.worker.handler import VirusScanHandler


@inject
def serve(handler: VirusScanHandler = Provide["handler"]):
    """Starts the VirusScanner Consumer (Worker) and a metrics server."""

    # Define Litestar app for metrics
    prometheus_config = PrometheusConfig(
        app_name="virusscanner", metrics_endpoint="/metrics"
    )

    app = Litestar(
        route_handlers=[], plugins=[PrometheusPlugin(config=prometheus_config)]
    )

    async def run_server():
        config = uvicorn.Config(app, host="0.0.0.0", port=9090, log_level="error")
        server = uvicorn.Server(config)
        await server.serve()

    async def run_all():
        await asyncio.gather(handler.run(), run_server())

    logging.info("Starting VirusScanner Consumer with Metrics on port 9090")
    try:
        asyncio.run(run_all())
    except KeyboardInterrupt:
        logging.info("Shutting down...")


@inject
async def set_target_epoch(redis_client=Provide["redis_client"]):
    """Signals all nodes to perform a coordinated reload by updating target_epoch. (Async)"""
    epoch_str = os.environ.get("TARGET_EPOCH")

    if epoch_str is not None:
        new_epoch = int(epoch_str)
    else:
        current = await redis_client.get("clamav:target_epoch")
        new_epoch = (int(current) if current else 0) + 1

    await redis_client.set("clamav:target_epoch", new_epoch)
    await redis_client.set("clamav:target_epoch_updated_at", time.time())
    logging.info(f"Target epoch set to {new_epoch}. Nodes will reload sequentially.")


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    container = Container()
    container.wire(modules=[__name__])

    command = sys.argv[1] if len(sys.argv) > 1 else "serve"

    if command == "set_epoch":
        asyncio.run(set_target_epoch())
    else:
        serve()


if __name__ == "__main__":
    main()
