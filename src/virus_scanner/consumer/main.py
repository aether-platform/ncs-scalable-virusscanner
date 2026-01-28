import os
import logging
import click
from .containers import Container

@click.command()
@click.option("--redis-host", default=lambda: os.getenv("REDIS_HOST", "localhost"), help="Redis host")
@click.option("--redis-port", default=lambda: int(os.getenv("REDIS_PORT", 6379)), type=int, help="Redis port")
@click.option("--clamd-url", default=lambda: os.getenv("CLAMD_URL", "tcp://127.0.0.1:3310"), help="ClamD connection URL (e.g. tcp://host:port or unix:///path/to/socket)")
@click.option("--queues", default=["scan_priority", "scan_normal"], multiple=True, help="Redis queues to monitor")
@click.option("--scan-mount", default=lambda: os.getenv("SCAN_MOUNT", "/tmp/virusscan"), help="Mount path for files to scan")
@click.option("--enable-memory-check/--no-memory-check", default=lambda: os.getenv("ENABLE_MEMORY_CHECK", "false").lower() == "true", help="Enable memory monitoring (default: disabled)")
@click.option("--min-free-memory-mb", default=lambda: int(os.getenv("MIN_FREE_MEMORY_MB", "500")), type=int, help="Minimum free memory in MB (default: 500)")
def main(redis_host, redis_port, clamd_url, queues, scan_mount, enable_memory_check, min_free_memory_mb):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    container = Container()
    container.config.from_dict({
        "redis_host": redis_host,
        "redis_port": redis_port,
        "clamd_url": clamd_url,
        "queues": queues,
        "scan_mount": scan_mount,
        "enable_memory_check": enable_memory_check,
        "min_free_memory_mb": min_free_memory_mb
    })
    
    handler = container.handler()
    handler.run()

if __name__ == "__main__":
    main()
