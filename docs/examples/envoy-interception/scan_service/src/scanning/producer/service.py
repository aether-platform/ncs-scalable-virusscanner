import json
import time
from typing import Any, Callable, Optional


class ScanProducerService:
    def __init__(
        self,
        redis_meta: Any,
        provider_factory: Callable[..., Any],
    ):
        self.redis_meta = redis_meta
        self.provider_factory = provider_factory

    def prepare_scan(self, file_hash: str) -> Any:
        # We use file_hash as the identifier in this implementation
        return self.provider_factory("STREAM", chunks_key=file_hash)

    def emit_task(self, file_hash: str, is_priority: bool = False):
        queue_name = "scan_queue_priority" if is_priority else "scan_queue_normal"
        task = {"hash": file_hash, "ts": time.time()}
        self.redis_meta.lpush(queue_name, json.dumps(task))

    def wait_for_result(self, file_hash: str, timeout: int = 20) -> Optional[str]:
        start = time.time()
        while time.time() - start < timeout:
            result = self.redis_meta.get(f"scan:{file_hash}")
            if result:
                return result
            time.sleep(0.5)
        return None
