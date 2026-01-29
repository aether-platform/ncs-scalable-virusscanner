from ..common.settings import BaseSettings


class ProducerSettings(BaseSettings):
    def __init__(
        self,
        redis_host: str,
        redis_port: int,
        scan_tmp_dir: str = "/tmp/virusscan",
        scan_file_threshold_mb: int = 10,
    ):
        super().__init__(
            redis_host=redis_host, redis_port=redis_port, scan_tmp_dir=scan_tmp_dir
        )
        self.scan_file_threshold_mb = scan_file_threshold_mb
