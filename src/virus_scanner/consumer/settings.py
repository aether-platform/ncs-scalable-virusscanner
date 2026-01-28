from typing import List

class Settings:
    def __init__(
        self, 
        redis_host: str, 
        redis_port: int, 
        clamd_url: str,
        queues: List[str], 
        scan_mount: str,
        enable_memory_check: bool = False,
        min_free_memory_mb: int = 500
    ):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.clamd_url = clamd_url
        self.queues = list(queues)
        self.scan_mount = scan_mount
        self.enable_memory_check = enable_memory_check
        self.min_free_memory_mb = min_free_memory_mb
