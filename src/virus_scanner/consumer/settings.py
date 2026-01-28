from typing import List

class Settings:
    def __init__(
        self, 
        redis_host: str, 
        redis_port: int, 
        clamd_url: str,
        queues: List[str], 
        scan_mount: str
    ):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.clamd_url = clamd_url
        self.queues = list(queues)
        self.scan_mount = scan_mount
