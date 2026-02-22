import logging
import socket
import struct
from typing import Tuple

from ...common.providers import DataProvider


class ScannerEngineClient:
    """
    Infrastructure client for interacting with the ClamAV (clamd) scanning engine.
    Handles the low-level INSTREAM protocol.
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

    def scan(self, provider: DataProvider) -> Tuple[bool, str]:
        """
        Performs a virus scan by streaming data from the provider to ClamAV.

        Args:
            provider: A DataProvider strategy that supplies the content to scan.

        Returns:
            A tuple of (is_infected, message).
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)
        try:
            s.connect((self.host, self.port))
            s.send(b"zINSTREAM\0")

            scan_success = False
            response = ""
            try:
                for chunk in provider.get_chunks():
                    s.send(struct.pack("!I", len(chunk)))
                    s.send(chunk)

                s.send(struct.pack("!I", 0))
                response = s.recv(4096).decode("utf-8").strip()
                scan_success = True
            finally:
                # Let provider cleanup
                provider.finalize(
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
            s.close()
