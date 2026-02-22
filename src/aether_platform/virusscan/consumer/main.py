import asyncio
import logging
import os
import sys
import time

from dependency_injector.wiring import Provide, inject

from .containers import Container
from .interfaces.worker.handler import VirusScanHandler


@inject
def serve(handler: VirusScanHandler = Provide[Container.handler]):
    """Starts the VirusScanner Consumer (Worker)."""
    # TODO: 優先４，通常1で構成する？
    asyncio.run(handler.run())


@inject
def set_target_epoch(redis_client=Provide[Container.redis_client]):
    """Signals all nodes to perform a coordinated reload by updating target_epoch."""
    epoch_str = os.environ.get("TARGET_EPOCH")

    if epoch_str is not None:
        new_epoch = int(epoch_str)
    else:
        current = redis_client.get("clamav:target_epoch")
        new_epoch = (int(current) if current else 0) + 1

    redis_client.set("clamav:target_epoch", new_epoch)
    redis_client.set("clamav:target_epoch_updated_at", time.time())
    logging.info(f"Target epoch set to {new_epoch}. Nodes will reload sequentially.")


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    container = Container()
    container.wire(modules=[__name__])

    command = sys.argv[1] if len(sys.argv) > 1 else "serve"

    if command == "set_epoch":
        set_target_epoch()
    else:
        serve()


if __name__ == "__main__":
    main()
