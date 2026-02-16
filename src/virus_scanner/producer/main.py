"""
Virus Scanner Producer (ICAP Server)

ICAP service that intercepts requests/responses from Squid, enqueues virus scan tasks to Redis,
and blocks malicious content.
"""

import json
import logging
import os
import socketserver

import click

from .containers import ProducerContainer

logger = logging.getLogger(__name__)


# Basic ICAP Server Implementation
class ICAPRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.service = self.server.service_instance
            self.redis = self.server.redis_client
            self.process_request()
        except Exception as e:
            logger.error(f"Error handling request: {e}")

    def process_request(self):
        # Read ICAP Header
        headers = {}
        method = None
        uri = None
        protocol = None

        # Parse Request Line
        line = self.rfile.readline().strip().decode("utf-8")
        if not line:
            return
        parts = line.split()
        if len(parts) >= 3:
            method, uri, protocol = parts[0], parts[1], parts[2]

        # Parse Headers
        while True:
            line = self.rfile.readline().strip().decode("utf-8")
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        logger.info(f"ICAP Request: {method} {uri}")

        if method == "OPTIONS":
            self.handle_options(uri)
        elif method == "REQMOD":
            self.handle_mod(uri, headers, mode="REQMOD")
        elif method == "RESPMOD":
            self.handle_mod(uri, headers, mode="RESPMOD")
        else:
            self.send_error(501, "Method not implemented")

    def handle_options(self, uri):
        response = (
            "ICAP/1.0 200 OK\r\n"
            "Methods: REQMOD, RESPMOD\r\n"
            "Service: VirusScanner/1.0\r\n"
            'ISTag: "vs-1.0"\r\n'
            "Transfer-Preview: *\r\n"
            "Max-Connections: 100\r\n"
            "Options-TTL: 3600\r\n"
            "\r\n"
        )
        self.wfile.write(response.encode())

    def handle_mod(self, uri, icap_headers, mode):
        # 1. Check Cache
        # If the URL is known to be CLEAN, return 204 immediately (Client sends nothing).
        if self.service.scanner.check_cache(uri):
            logger.info(f"CACHE HIT: {uri} - Skipping Scan")
            self.send_response(204)
            return

        # Extract Encapsulated header to find body offset
        encapsulated = icap_headers.get("encapsulated", "")

        # We need to parse request/response headers from the encapsulated body
        # For simplicity in this specialized scanner, we focus on the BODY processing.
        # But Squid sends headers first.

        # Read encapsulated parts logic is complex for full ICAP.
        # Implements a simplified approach: Scan EVERYTHING if body is present.

        # 1. Receive Body (Chunks)
        # ICAP uses chunked encoding for the body sent to us.

        # Identify if body exists
        has_body = "res-body=" in encapsulated or "req-body=" in encapsulated

        if not has_body:
            # No body, nothing to scan. Allow 204.
            self.send_response(204)
            return

        # Determine Priority
        is_priority = False
        # Logic to check priority (e.g. from X-Client-IP header passing through)
        # For now, simple logic or always false unless specified

        # Prepare Scan Task
        task_id, provider = self.service.scanner.prepare_scan(is_priority=is_priority)
        self.service.scanner.emit_task(task_id, is_priority=is_priority)

        # Read Chunks
        while True:
            line = self.rfile.readline().decode("utf-8")
            if not line:
                break  # Unexpected EOF

            # Helper to parse chunk size
            try:
                chunk_size_hex = line.strip().split(";")[0]
                chunk_size = int(chunk_size_hex, 16)
            except ValueError:
                logger.error(f"Invalid chunk size: {line}")
                break

            if chunk_size == 0:
                break  # End of preview or body

            # Read chunk data
            data = self.rfile.read(chunk_size)
            self.rfile.read(2)  # CRLF

            provider.push_chunk(data.encode("utf-8") if isinstance(data, str) else data)

        # Finalize and Wait
        provider.finalize_push()
        self.service.scanner.record_ingest_time(task_id)

        status_raw = self.service.scanner.wait_for_result(task_id, timeout=30)

        if status_raw:
            status_data = json.loads(status_raw.decode("utf-8"))
            if status_data.get("status") == "INFECTED":
                self.send_blocked_response(status_data.get("virus", "Unknown"))
                return

        # Clean, allow traffic
        # Store in cache so we skip next time
        self.service.scanner.store_cache(uri)
        self.send_response(204)

    def send_response(self, code):
        res = f"ICAP/1.0 {code} OK\r\n\r\n"
        self.wfile.write(res.encode())

    def send_blocked_response(self, virus_name):
        # Return 403 Forbidden via ICAP 200 OK (Modified)
        html = f"<html><body><h1>Virus Detected!</h1><p>The file you are trying to access is infected with: <b>{virus_name}</b></p></body></html>"

        # Construct HTTP Response
        http_resp = (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(html)}\r\n"
            "\r\n"
            f"{html}"
        )

        icap_res = (
            "ICAP/1.0 200 OK\r\n"
            'ISTag: "vs-1.0"\r\n'
            "Encapsulated: res-hdr=0, res-body={}\r\n"
            "\r\n"
        ).format(len(http_resp.split("\r\n\r\n")[0]) + 4)  # Approximation, simplified

        # Correct construction needs precise offset calculation.
        # For simplicity, let's use a simpler 200 OK if we modify.
        # But we need to wrap the HTTP response.

        self.wfile.write(icap_res.encode())
        self.wfile.write(http_resp.encode())


class ICAPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(
        self, server_address, RequestHandlerClass, service_instance, redis_client
    ):
        super().__init__(server_address, RequestHandlerClass)
        self.service_instance = service_instance
        self.redis_client = redis_client


class ProducerService:
    def __init__(self, container: "ProducerContainer"):
        self.redis = container.redis_client()
        self.settings = container.settings()
        self.container = container
        self.server = None

    def start(self):
        port = int(os.environ.get("PRODUCER_PORT", "1344"))
        logger.info(f"Starting ICAP Server on port {port}...")

        self.server = ICAPServer(
            ("0.0.0.0", port),
            ICAPRequestHandler,
            self.container.scanner_service(),
            self.redis,
        )
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            pass


@click.command()
@click.option("--redis-host", envvar="REDIS_HOST", default="localhost")
@click.option("--redis-port", envvar="REDIS_PORT", default=6379, type=int)
@click.option("--producer-port", envvar="PRODUCER_PORT", default=1344, type=int)
def serve(redis_host, redis_port, producer_port):
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    container = ProducerContainer()
    container.config.from_dict(
        {
            "redis_host": redis_host,
            "redis_port": redis_port,
        }
    )

    os.environ["PRODUCER_PORT"] = str(producer_port)
    service = ProducerService(container)
    service.start()


if __name__ == "__main__":
    serve()
