"""NATS notification publisher for scan results."""

import json
import logging
import uuid
from datetime import datetime, timezone

import nats
from nats.aio.client import Client as NatsClient

logger = logging.getLogger(__name__)


class NatsNotificationPublisher:
    """Publishes scan result notifications to NATS for real-time delivery to VS Code."""

    def __init__(self, nats_url: str = "nats://localhost:4222"):
        self._url = nats_url
        self._nc: NatsClient | None = None

    async def connect(self) -> None:
        """Establish connection to NATS with automatic reconnection."""
        try:
            self._nc = await nats.connect(
                servers=self._url,
                max_reconnect_attempts=-1,
                reconnect_time_wait=2,
                name="virusscanner-consumer",
            )
            logger.info(f"Connected to NATS at {self._url}")
        except Exception as e:
            logger.error(f"Failed to connect to NATS: {e}")
            self._nc = None

    async def disconnect(self) -> None:
        """Drain and close NATS connection."""
        if self._nc:
            try:
                await self._nc.drain()
            except Exception as e:
                logger.warning(f"Error draining NATS connection: {e}")
            self._nc = None

    @property
    def is_connected(self) -> bool:
        return self._nc is not None and self._nc.is_connected

    async def publish_scan_result(
        self,
        tenant_id: str,
        user_id: str,
        is_infected: bool,
        virus_name: str | None = None,
        stream_id: str | None = None,
        bytes_scanned: int = 0,
        scan_duration_ms: float = 0,
    ) -> None:
        """Publish a scan result notification to NATS.

        Args:
            tenant_id: Tenant identifier.
            user_id: User identifier.
            is_infected: Whether a threat was detected.
            virus_name: Name of detected threat (if infected).
            stream_id: Task/stream identifier for correlation.
            bytes_scanned: Number of bytes scanned.
            scan_duration_ms: Scan duration in milliseconds.
        """
        if not self.is_connected:
            return

        event_type = "scan_infected" if is_infected else "scan_completed"
        severity = "error" if is_infected else "info"

        if is_infected:
            title = "Threat Detected"
            message = f"Threat '{virus_name}' found in uploaded content."
        else:
            title = "Scan Complete"
            message = "Content scanned — no threats found."

        subject = f"aether.notify.user.{tenant_id}.{user_id}.security.{event_type}"

        payload = {
            "version": "1.0",
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "virusscanner-consumer",
            "tenant_id": tenant_id,
            "user_id": user_id,
            "category": "security",
            "event_type": event_type,
            "severity": severity,
            "title": title,
            "message": message,
            "data": {
                "stream_id": stream_id,
                "virus_name": virus_name,
                "bytes_scanned": bytes_scanned,
                "scan_duration_ms": round(scan_duration_ms, 1),
            },
            "actions": (
                [{"label": "View Details", "command": "aetherplatform.openConsole"}]
                if is_infected
                else []
            ),
        }

        try:
            await self._nc.publish(subject, json.dumps(payload).encode("utf-8"))
            logger.debug(f"Published notification to {subject}")
        except Exception as e:
            logger.error(f"Failed to publish NATS notification: {e}")
