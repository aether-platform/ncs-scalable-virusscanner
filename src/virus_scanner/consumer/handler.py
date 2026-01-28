import os
import time
import json
import logging
from datetime import datetime
from urllib.parse import urlparse
import redis
import clamd
from .settings import Settings

class VirusScanHandler:
    def __init__(self, redis_client: redis.Redis, settings: Settings):
        self.redis = redis_client
        self.settings = settings
        self.logger = logging.getLogger(__name__)

    def _get_clamd_client(self) -> clamd.ClamdUnixSocket | clamd.ClamdNetworkSocket:
        """Parses clamd_url and returns the appropriate client."""
        url = urlparse(self.settings.clamd_url)
        
        if url.scheme == 'unix':
            # unix:///path/to/socket -> path is url.path
            return clamd.ClamdUnixSocket(path=url.path)
        elif url.scheme == 'tcp':
            # tcp://host:port
            host = url.hostname or 'localhost'
            port = url.port or 3310
            return clamd.ClamdNetworkSocket(host=host, port=port)
        else:
            # Fallback or error
            raise ValueError(f"Unsupported ClamAV URL scheme: {url.scheme}. Use 'tcp://' or 'unix://'.")

    def _scan_file(self, file_path: str):
        """Scans a file using ClamAV daemon."""
        try:
            cd = self._get_clamd_client()
            if cd.ping() != 'PONG':
                self.logger.error("Clamd not responsive")
                return "error", "Clamd not responsive"
            
            full_path = os.path.join(self.settings.scan_mount, file_path.lstrip("/"))
            
            if not os.path.exists(full_path):
                self.logger.error(f"File not found: {full_path}")
                return "not_found", f"File {file_path} not found in mount"

            self.logger.info(f"Scanning file: {full_path}")
            result = cd.scan(full_path)
            
            if full_path in result:
                status, reason = result[full_path]
                if status == 'OK':
                    return "clean", None
                elif status == 'FOUND':
                    return "infected", reason
                else:
                    # 'ERROR' or other status
                    return "error", f"ClamAV {status}: {reason}"
            
            return "error", "Unexpected clamd response"
        except Exception as e:
            self.logger.exception(f"Error during scan: {e}")
            return "error", str(e)

    def run(self):
        self.logger.info(f"Starting Virus Scanner Request Handler (Redis: {self.settings.redis_host}, Clamd: {self.settings.clamd_url})")
        
        try:
            self.redis.ping()
        except Exception as e:
            self.logger.critical(f"Could not connect to Redis: {e}")
            return

        while True:
            try:
                task_data_raw = self.redis.blpop(self.settings.queues, timeout=5)
                
                if not task_data_raw:
                    continue
                
                queue_name, task_json = task_data_raw
                self.logger.info(f"Received task from {queue_name}")
                
                try:
                    task = json.loads(task_json)
                    task_id = task.get("id", "unknown")
                    file_path = task.get("file_path")
                    tenant_id = task.get("tenant_id", "default")
                    
                    if not file_path:
                        self.logger.error("Task missing file_path")
                        continue
                    
                    start_time = time.time()
                    result, reason = self._scan_file(file_path)
                    duration = time.time() - start_time
                    
                    result_record = {
                        "id": task_id,
                        "tenant_id": tenant_id,
                        "file_path": file_path,
                        "result": result,
                        "reason": reason,
                        "duration_seconds": duration,
                        "timestamp": datetime.utcnow().isoformat(),
                        "queue": queue_name
                    }
                    
                    print(json.dumps(result_record), flush=True)

                except json.JSONDecodeError:
                    self.logger.error(f"Invalid task JSON: {task_json}")
                    
            except redis.ConnectionError:
                self.logger.error("Redis connection lost. Retrying in 5 seconds...")
                time.sleep(5)
            except Exception as e:
                self.logger.exception(f"Unexpected error in main loop: {e}")
                time.sleep(1)
        
