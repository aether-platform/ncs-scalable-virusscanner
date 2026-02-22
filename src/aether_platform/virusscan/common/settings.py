import os


class BaseSettings:
    """Common settings shared between Producer and Consumer."""

    def __init__(
        self,
        redis_host: str = None,
        redis_port: int = None,
        scan_tmp_dir: str = None,
    ):
        self.redis_host = redis_host or os.getenv("REDIS_HOST", "localhost")
        try:
            self.redis_port = int(redis_port or os.getenv("REDIS_PORT", 6379))
        except (ValueError, TypeError):
            self.redis_port = 6379
        self.scan_tmp_dir = scan_tmp_dir or os.getenv("SCAN_TMP_DIR", "/tmp/virusscan")
