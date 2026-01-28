from typing import List

class ProducerSettings:
    def __init__(
        self, 
        redis_host: str, 
        redis_port: int,
        scan_tmp_dir: str = "/tmp/virusscan",
        scan_file_threshold_mb: int = 10
    ):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.scan_tmp_dir = scan_tmp_dir
        self.scan_file_threshold_mb = scan_file_threshold_mb
