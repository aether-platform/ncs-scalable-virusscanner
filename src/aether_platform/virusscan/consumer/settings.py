import os
from typing import List, Union

from ..common.settings import BaseSettings


class Settings(BaseSettings):
    """Configuration for the VirusScanner Consumer."""

    def __init__(
        self,
        redis_host: str = None,
        redis_port: int = None,
        clamd_url: str = None,
        queues: Union[List[str], str] = None,
        scan_mount: str = None,
        enable_memory_check: bool = None,
        min_free_memory_mb: int = None,
    ):
        super().__init__(
            redis_host=redis_host, redis_port=redis_port, scan_tmp_dir=scan_mount
        )
        self.clamd_url = clamd_url or os.getenv("CLAMD_URL", "tcp://127.0.0.1:3310")

        # Handle queues from env or list
        if isinstance(queues, str):
            self.queues = [q.strip() for q in queues.split(",")]
        elif isinstance(queues, list):
            self.queues = queues
        else:
            env_queues = os.getenv("QUEUES")
            self.queues = (
                [q.strip() for q in env_queues.split(",")]
                if env_queues
                else ["scan_priority", "scan_normal"]
            )

        self.scan_mount = self.scan_tmp_dir

        # Memory checks
        self.enable_memory_check = (
            enable_memory_check
            if enable_memory_check is not None
            else (os.getenv("ENABLE_MEMORY_CHECK", "false").lower() == "true")
        )
        try:
            self.min_free_memory_mb = int(
                min_free_memory_mb or os.getenv("MIN_FREE_MEMORY_MB", 500)
            )
        except (ValueError, TypeError):
            self.min_free_memory_mb = 500
