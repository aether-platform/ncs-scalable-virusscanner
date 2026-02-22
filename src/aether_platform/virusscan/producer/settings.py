import os

from ..common.settings import BaseSettings


class ProducerSettings(BaseSettings):
    """Configuration for the VirusScanner Producer."""

    def __init__(
        self,
        redis_host: str = None,
        redis_port: int = None,
        scan_tmp_dir: str = None,
        scan_file_threshold_mb: int = None,
        grpc_port: int = None,
        tenant_id: str = None,
    ):
        super().__init__(
            redis_host=redis_host, redis_port=redis_port, scan_tmp_dir=scan_tmp_dir
        )
        try:
            self.scan_file_threshold_mb = int(
                scan_file_threshold_mb or os.getenv("SCAN_FILE_THRESHOLD_MB", 10)
            )
        except (ValueError, TypeError):
            self.scan_file_threshold_mb = 10

        try:
            self.grpc_port = int(grpc_port or os.getenv("GRPC_PORT", 50051))
        except (ValueError, TypeError):
            self.grpc_port = 50051

        self.tenant_id = tenant_id or os.getenv("TENANT_ID", "default-tenant")
