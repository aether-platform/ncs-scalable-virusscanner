class BaseSettings:
    """Common settings shared between Producer and Consumer."""

    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        scan_tmp_dir: str = "/tmp/virusscan",
    ):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.scan_tmp_dir = scan_tmp_dir
