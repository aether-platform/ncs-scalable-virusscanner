from typing import List

from ..common.settings import BaseSettings


class Settings(BaseSettings):
    def __init__(
        self,
        redis_host: str,
        redis_port: int,
        clamd_url: str,
        queues: List[str],
        scan_mount: str,
        enable_memory_check: bool = False,
        min_free_memory_mb: int = 500,
    ):
        super().__init__(
            redis_host=redis_host, redis_port=redis_port, scan_tmp_dir=scan_mount
        )
        self.clamd_url = clamd_url
        self.queues = list(queues)
        self.scan_mount = self.scan_tmp_dir  # Alias for consistency
        self.enable_memory_check = enable_memory_check
        self.min_free_memory_mb = min_free_memory_mb
