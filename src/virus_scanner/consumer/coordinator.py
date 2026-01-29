import logging
import os
import time
from urllib.parse import urlparse

import clamd
import redis


class ClusterCoordinator:
    def __init__(self, redis_client: redis.Redis, clamd_url: str):
        self.redis = redis_client
        self.clamd_url = clamd_url
        self.logger = logging.getLogger(__name__)
        self.pod_name = os.getenv("HOSTNAME", "unknown-pod")
        self.current_epoch = 0
        self.last_heartbeat = 0

    def heartbeat(self):
        """Notifies Redis that this node is alive."""
        now = time.time()
        if now - self.last_heartbeat < 30:
            return

        try:
            heartbeat_key = f"clamav:heartbeat:{self.pod_name}"
            # Heartbeat value includes pod name and current epoch for monitoring
            self.redis.set(heartbeat_key, f"{now}|{self.current_epoch}", ex=60)
            self.redis.sadd("clamav:active_nodes", self.pod_name)
            self.logger.debug(
                f"Heartbeat sent for {self.pod_name} (Epoch: {self.current_epoch})"
            )
            self.last_heartbeat = now
        except Exception as e:
            self.logger.warning(f"Failed to send heartbeat: {e}")

    def handle_sequential_update(self):
        """Coordinates a sequential Reload across nodes using Redis locks and Surge."""
        target_info = self.redis.mget(
            "clamav:target_epoch", "clamav:target_epoch_updated_at"
        )
        if not target_info[0]:
            return

        target_epoch = int(target_info[0])
        if target_epoch <= self.current_epoch:
            return

        lock_key = "clamav:update_lock"
        lock_ttl = 600

        if self.redis.set(lock_key, self.pod_name, ex=lock_ttl, nx=True):
            self.logger.info(f"Acquired update lock. Updating to epoch {target_epoch}")
            try:
                deployment_name = os.getenv("DEPLOYMENT_NAME")
                active_nodes = self._get_active_node_count()

                if active_nodes == 1 and deployment_name:
                    self.logger.info(
                        "Single node detected. Requesting Surge (Scale-up)."
                    )
                    # Request scale-up to 2 via Redis list for KEDA
                    # We clear the list first to avoid double requests
                    self.redis.delete("clamav:scaling_request")
                    self.redis.lpush("clamav:scaling_request", "surge", "surge")

                    # Release lock and wait for the second node to appear
                    self.redis.delete(lock_key)
                    self.logger.info(
                        "Released lock while waiting for surge infrastructure..."
                    )

                    start_wait = time.time()
                    while self._get_active_node_count() < 2:
                        if time.time() - start_wait > 300:
                            break
                        time.sleep(10)
                        self.heartbeat()

                    # Re-acquire lock to finish the job
                    if not self.redis.set(
                        lock_key, self.pod_name, ex=lock_ttl, nx=True
                    ):
                        self.logger.info(
                            "Another node took the update slot after surge. Relinquishing."
                        )
                        return

                # Trigger ClamAV Reload
                self._trigger_reload()
                self.current_epoch = target_epoch

                # Check if we should scale back down
                self._handle_scale_down(target_epoch)

            except Exception as e:
                self.logger.error(f"Error during coordinated reload: {e}")
            finally:
                self.redis.delete(lock_key)

    def _get_active_node_count(self) -> int:
        try:
            nodes = self.redis.smembers("clamav:active_nodes")
            active_count = 0
            for node_bin in nodes:
                node = node_bin.decode("utf-8")
                heartbeat = self.redis.get(f"clamav:heartbeat:{node}")
                if heartbeat:
                    active_count += 1
                else:
                    self.redis.srem("clamav:active_nodes", node_bin)
            return active_count
        except Exception as e:
            self.logger.warning(f"Failed to count active nodes: {e}")
            return 1

    def _trigger_reload(self):
        url = urlparse(self.clamd_url)
        if url.scheme == "tcp":
            cd = clamd.ClamdNetworkSocket(host=url.hostname, port=url.port)
        else:
            cd = clamd.ClamdUnixSocket(path=url.path)

        self.logger.info("Triggering ClamAV Reload...")
        cd.reload()

        start_check = time.time()
        while time.time() - start_check < 60:
            try:
                if cd.ping() == "PONG":
                    self.logger.info("Reload successful. ClamAV is ready.")
                    return
            except Exception:
                pass
            time.sleep(2)

    def _handle_scale_down(self, target_epoch: int):
        """If all nodes are updated, clear scaling requests to allow KEDA scale-down."""
        nodes = self.redis.smembers("clamav:active_nodes")
        all_updated = True
        for node_bin in nodes:
            hb = self.redis.get(f"clamav:heartbeat:{node_bin.decode('utf-8')}")
            if hb:
                _, epoch = hb.split("|")
                if int(epoch) < target_epoch:
                    all_updated = False
                    break

        if all_updated:
            self.logger.info("All nodes updated. Terminating surge request.")
            self.redis.delete("clamav:scaling_request")
