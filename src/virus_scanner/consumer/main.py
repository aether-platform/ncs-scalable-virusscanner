import logging
import time

import click

from .containers import Container


@click.command()
@click.option(
    "--redis-host",
    envvar="REDIS_HOST",
    default="localhost",
    help="Redis host",
)
@click.option(
    "--redis-port",
    envvar="REDIS_PORT",
    default=6379,
    type=int,
    help="Redis port",
)
@click.option(
    "--clamd-url",
    envvar="CLAMD_URL",
    default="tcp://127.0.0.1:3310",
    help="ClamD connection URL (e.g. tcp://host:port or unix:///path/to/socket)",
)
@click.option(
    "--queues",
    default=["scan_priority", "scan_normal"],
    multiple=True,
    help="Redis queues to monitor",
)
@click.option(
    "--scan-mount",
    envvar="SCAN_MOUNT",
    default="/tmp/virusscan",
    help="Mount path for files to scan",
)
@click.option(
    "--enable-memory-check/--no-memory-check",
    envvar="ENABLE_MEMORY_CHECK",
    default=False,
    help="Enable memory monitoring (default: disabled)",
)
@click.option(
    "--min-free-memory-mb",
    envvar="MIN_FREE_MEMORY_MB",
    default=500,
    type=int,
    help="Minimum free memory in MB (default: 500)",
)
def main(
    redis_host,
    redis_port,
    clamd_url,
    queues,
    scan_mount,
    enable_memory_check,
    min_free_memory_mb,
):
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    container = Container()
    container.config.from_dict(
        {
            "redis_host": redis_host,
            "redis_port": redis_port,
            "clamd_url": clamd_url,
            "queues": queues,
            "scan_mount": scan_mount,
            "enable_memory_check": enable_memory_check,
            "min_free_memory_mb": min_free_memory_mb,
        }
    )

    handler = container.handler()
    handler.run()


@click.command()
@click.option(
    "--epoch",
    default=None,
    type=int,
    help="Target epoch to set. If omitted, increments current.",
)
def set_target_epoch(epoch):
    """Signals all nodes to perform a coordinated reload by updating target_epoch."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )
    container = Container()
    redis_client = container.redis()

    if epoch is not None:
        new_epoch = epoch
    else:
        current = redis_client.get("clamav:target_epoch")
        new_epoch = (int(current) if current else 0) + 1

    redis_client.set("clamav:target_epoch", new_epoch)
    redis_client.set("clamav:target_epoch_updated_at", time.time())
    logging.info(
        f"Target epoch set to {new_epoch}. Nodes will reload sequentially (with surge if needed)."
    )


@click.command()
@click.argument("deployment-name")
@click.option("--namespace", default=None, help="Kubernetes namespace")
def rollout_restart(deployment_name, namespace):
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )
    container = Container()
    handler = container.handler()
    handler.trigger_rollout_restart(deployment_name, namespace)


if __name__ == "__main__":
    # This script is used as an entrypoint for both the handler and the restart utility.
    # In pyproject.toml, we can map different names to these functions.
    main()
