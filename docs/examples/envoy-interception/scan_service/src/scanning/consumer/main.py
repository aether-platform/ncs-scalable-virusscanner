import io
import json
import time

import clamd
from dependency_injector import providers
from dependency_injector.wiring import Provide, inject

from ..core.containers import Container, create_container


class WorkerController:
    @inject
    def __init__(
        self,
        redis_meta=Provide[Container.redis_meta],
        redis_client=Provide[Container.redis_client],
        clamav=Provide[Container.clamav],
    ):
        self.redis_meta = redis_meta
        self.redis_client = redis_client
        self.clamav = clamav

    def run(self):
        print("Consumer (Scan Worker) started. Ratio 4:1 enabled.")

        schedule = ["scan_queue_priority"] * 4 + ["scan_queue_normal"]
        idx = 0

        while True:
            target_queue = schedule[idx % 5]
            idx += 1

            task_json = self.redis_meta.rpop(target_queue)

            if not task_json:
                # Fallback
                for q in ["scan_queue_priority", "scan_queue_normal"]:
                    if q == target_queue:
                        continue
                    task_json = self.redis_meta.rpop(q)
                    if task_json:
                        break

                if not task_json:
                    time.sleep(0.5)
                    continue

            task = json.loads(task_json)
            file_hash = task["hash"]
            print(f"[Consumer] Processing {file_hash} from {target_queue}")

            # Use data provider pattern
            body_bytes = self.redis_client.get(f"data:{file_hash}")
            if not body_bytes:
                continue

            try:
                body_stream = io.BytesIO(body_bytes)
                scan_result = self.clamav.instream(body_stream)
                status, virus_name = scan_result["stream"]

                res = "INFECTED" if status == "FOUND" else "CLEAN"
                print(f"[Consumer] Result for {file_hash}: {res}")
                self.redis_meta.setex(f"scan:{file_hash}", 3600, res)
                self.redis_client.delete(f"data:{file_hash}")

            except Exception as e:
                print(f"[Consumer] ClamAV Error: {e}")


def main():
    container = create_container()

    # Configure ClamAV provider
    container.config.clamav_host.from_env("CLAMAV_HOST", "localhost")
    container.config.clamav_port.from_env("CLAMAV_PORT", "3310", as_=int)

    container.clamav = providers.Singleton(
        clamd.ClamdNetworkSocket,
        host=container.config.clamav_host,
        port=container.config.clamav_port,
    )

    container.wire(modules=[__name__])

    controller = WorkerController()
    controller.run()


if __name__ == "__main__":
    main()
