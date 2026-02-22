import logging
import os
import time
from urllib.parse import urlparse

import clamd
from dependency_injector.wiring import Provide, inject

from aether_platform.virusscan.common.queue.provider import (
    QueueProvider,
    StateStoreProvider,
)


class ClusterCoordinator:
    """
    Infrastructure component that coordinates ClamAV reload operations across a cluster.
    Uses StateStoreProvider as a distributed state store for heartbeats and Surge locks,
    and QueueProvider for emitting surge scaling requests.
    """

    @inject
    def __init__(
        self,
        queue_provider: QueueProvider = Provide["queue_provider"],
        state_store: StateStoreProvider = Provide["state_store_provider"],
        clamd_url: str = Provide["settings.clamd_url"],
    ):
        """
        Initializes the cluster coordinator.

        Args:
            queue_provider: Distributed queue provider for messaging.
            state_store: Distributed state store provider for cluster state.
            clamd_url: URL for the local clamd instance.
        """
        self.queue_provider = queue_provider
        self.state_store = state_store
        self.clamd_url = clamd_url
        self.logger = logging.getLogger(__name__)
        self.pod_name = os.getenv("HOSTNAME", "unknown-pod")
        self.current_epoch = 0
        self.last_heartbeat = 0

    async def _get_active_node_count(self) -> int:
        """Internal helper to count the number of live nodes in the cluster."""
        try:
            nodes = await self.state_store.smembers("clamav:active_nodes")
            active_count = 0
            for node_bin in nodes:
                node = (
                    node_bin.decode("utf-8")
                    if isinstance(node_bin, bytes)
                    else str(node_bin)
                )
                heartbeat = await self.state_store.get(f"clamav:heartbeat:{node}")
                if heartbeat:
                    active_count += 1
                else:
                    await self.state_store.srem("clamav:active_nodes", node)
            return active_count
        except Exception as e:
            self.logger.warning(f"Failed to count active nodes: {e}")
            return 1

    def _trigger_reload(self):
        """Internal helper to send the RELOAD command to the local ClamAV instance."""
        url = urlparse(self.clamd_url)
        if url.scheme == "tcp":
            cd = clamd.ClamdNetworkSocket(host=url.hostname, port=url.port)
        else:
            cd = clamd.ClamdUnixSocket(path=url.path)

        self.logger.info("Triggering ClamAV Reload...")
        try:
            cd.reload()
        except Exception as e:
            self.logger.error(f"Reload command failed: {e}")
            return

        start_check = time.time()
        while time.time() - start_check < 60:
            try:
                if cd.ping() == "PONG":
                    self.logger.info("Reload successful. ClamAV is ready.")
                    return
            except Exception:
                pass
            time.sleep(2)

    async def _handle_scale_down(self, target_epoch: int):
        """Internal helper to clear surge requests once all nodes have synchronized."""
        nodes = await self.state_store.smembers("clamav:active_nodes")
        all_updated = True
        for node_bin in nodes:
            node = (
                node_bin.decode("utf-8")
                if isinstance(node_bin, bytes)
                else str(node_bin)
            )
            hb_raw = await self.state_store.get(f"clamav:heartbeat:{node}")
            if hb_raw:
                hb = (
                    hb_raw.decode("utf-8") if isinstance(hb_raw, bytes) else str(hb_raw)
                )
                try:
                    _, epoch = hb.split("|")
                    if int(epoch) < target_epoch:
                        all_updated = False
                        break
                except ValueError:
                    continue

        if all_updated:
            self.logger.info("All nodes updated. Terminating surge request.")
            await self.state_store.delete("clamav:scaling_request")

    async def heartbeat(self):
        """
        Publishes a heartbeat to the cluster registry.
        Should be called periodically in the main loop.
        """
        now = time.time()
        if now - self.last_heartbeat < 30:
            return

        try:
            heartbeat_key = f"clamav:heartbeat:{self.pod_name}"
            # Heartbeat value includes pod name and current epoch for monitoring
            await self.state_store.set(
                heartbeat_key, f"{now}|{self.current_epoch}", ex=60
            )
            await self.state_store.sadd("clamav:active_nodes", self.pod_name)
            self.logger.debug(
                f"Heartbeat sent for {self.pod_name} (Epoch: {self.current_epoch})"
            )
            self.last_heartbeat = now
        except Exception as e:
            self.logger.warning(f"Failed to send heartbeat: {e}")

    async def handle_sequential_update(self):
        """
        Main coordination logic for performing zero-downtime reloads.
        Uses surge scaling to maintain capacity while nodes reload sequentially.
        """
        target_info = await self.state_store.mget(
            "clamav:target_epoch", "clamav:target_epoch_updated_at"
        )
        if not target_info or not target_info[0]:
            return

        target_epoch_raw = target_info[0]
        try:
            target_epoch = int(
                target_epoch_raw.decode("utf-8")
                if isinstance(target_epoch_raw, bytes)
                else target_epoch_raw
            )
        except (ValueError, TypeError):
            return

        if target_epoch <= self.current_epoch:
            return

        lock_key = "clamav:update_lock"
        lock_ttl = 600

        if await self.state_store.set(lock_key, self.pod_name, ex=lock_ttl, nx=True):
            self.logger.info(f"Acquired update lock. Updating to epoch {target_epoch}")
            try:
                deployment_name = os.getenv("DEPLOYMENT_NAME")
                active_nodes = await self._get_active_node_count()

                if active_nodes == 1 and deployment_name:
                    self.logger.info(
                        "Single node detected. Requesting Surge (Scale-up) and returning."
                    )
                    await self.state_store.delete("clamav:scaling_request")
                    await self.queue_provider.push("clamav:scaling_request", "surge")
                    return

                # Trigger ClamAV Reload
                self._trigger_reload()
                self.current_epoch = target_epoch

                # Check if we should scale back down
                await self._handle_scale_down(target_epoch)

            except Exception as e:
                self.logger.error(f"Error during coordinated reload: {e}")
            finally:
                await self.state_store.delete(lock_key)
