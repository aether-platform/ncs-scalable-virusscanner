import asyncio
import logging
import struct
from typing import Tuple

from ...common.providers import DataProvider


class ScannerEngineClient:
    """
    Infrastructure client for interacting with the ClamAV (clamd) scanning engine.
    Handles the low-level INSTREAM protocol asynchronously.
    """

    def __init__(self, clamd_url: str):
        """
        Initializes the ClamAV client.

        Args:
            clamd_url: The URL for the clamd service (e.g., tcp://127.0.0.1:3310).
        """
        from urllib.parse import urlparse

        url = urlparse(clamd_url)
        self.host = url.hostname or "localhost"
        self.port = url.port or 3310
        self.logger = logging.getLogger(__name__)

    async def scan(self, provider: DataProvider) -> Tuple[bool, str]:
        """
        Performs a virus scan by streaming data from the provider to ClamAV asynchronously.

        Args:
            provider: A DataProvider strategy that supplies the content to scan.

        Returns:
            A tuple of (is_infected, message).
        """
        reader, writer = await asyncio.open_connection(self.host, self.port)
        try:
            writer.write(b"zINSTREAM\0")
            await writer.drain()

            scan_success = False
            response = ""
            try:
                async for chunk in provider.get_chunks():
                    writer.write(struct.pack("!I", len(chunk)))
                    writer.write(chunk)
                    await writer.drain()

                writer.write(struct.pack("!I", 0))
                await writer.drain()

                # Read response
                data = await reader.read(4096)
                response = data.decode("utf-8").strip()
                scan_success = True
            finally:
                # Let provider cleanup (now async)
                await provider.finalize(
                    scan_success, "FOUND" in response if scan_success else False
                )

            if scan_success:
                if "FOUND" in response:
                    return True, response
                return False, ""
            raise Exception("ClamAV communication failed")
        except Exception as e:
            self.logger.error(f"Engine scan error: {e}")
            raise
        finally:
            writer.close()
            await writer.wait_closed()
