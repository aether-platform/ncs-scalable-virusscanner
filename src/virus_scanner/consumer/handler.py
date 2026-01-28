import os
import time
import json
import logging
import socket
import struct
from datetime import datetime
from urllib.parse import urlparse
import redis
import clamd
from .settings import Settings

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

class VirusScanHandler:
    def __init__(self, redis_client: redis.Redis, settings: Settings):
        self.redis = redis_client
        self.settings = settings
        self.logger = logging.getLogger(__name__)

    def _get_free_memory_mb(self) -> float:
        """Get available memory in MB"""
        if not self.settings.enable_memory_check:
            return float('inf')  # No limit if disabled
        
        if HAS_PSUTIL:
            vm = psutil.virtual_memory()
            return vm.available / (1024 * 1024)
        return float('inf')  # No limit if psutil not available

    def _scan_with_clamav_stream(self, data: bytes, clamd_host: str, clamd_port: int) -> tuple[bool, str]:
        """
        Scan data using ClamAV INSTREAM protocol (chunked transfer)
        Based on experiment/scanner.py implementation
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((clamd_host, clamd_port))
            
            # Send INSTREAM command
            s.send(b"zINSTREAM\0")
            
            # Chunked sending (4KB chunks)
            chunk_size = 4096
            data_len = len(data)
            offset = 0
            remaining = data_len
            
            while remaining > 0:
                chunk = data[offset:offset+chunk_size]
                l = len(chunk)
                s.send(struct.pack('!I', l))  # Send chunk length (big-endian)
                s.send(chunk)
                offset += l
                remaining -= l
            
            # Send terminator
            s.send(struct.pack('!I', 0))
            
            # Receive response
            response = s.recv(4096).decode('utf-8').strip()
            s.close()
            
            if "FOUND" in response:
                return True, response
            return False, ""
        except Exception as e:
            self.logger.error(f"ClamAV INSTREAM error: {e}")
            return False, f"Error: {str(e)}"

    def _get_clamd_client(self) -> clamd.ClamdUnixSocket | clamd.ClamdNetworkSocket:
        """Parses clamd_url and returns the appropriate client."""
        url = urlparse(self.settings.clamd_url)
        
        if url.scheme == 'unix':
            return clamd.ClamdUnixSocket(path=url.path)
        elif url.scheme == 'tcp':
            host = url.hostname or 'localhost'
            port = url.port or 3310
            return clamd.ClamdNetworkSocket(host=host, port=port)
        else:
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
                    return "error", f"ClamAV {status}: {reason}"
            
            return "error", "Unexpected clamd response"
        except Exception as e:
            self.logger.exception(f"Error during scan: {e}")
            return "error", str(e)

    def _process_task_new_format(self, task_data: str, queue_name: str):
        """
        Process task in new format: taskID|MODE|TIMESTAMP|CONTENT
        Based on experiment/scanner.py
        """
        parts = task_data.split("|", 3)
        if len(parts) < 4:
            self.logger.error(f"Invalid task format: {task_data}")
            return
        
        task_id, mode, timestamp_str, content = parts
        push_time = int(timestamp_str)
        
        # Calculate queue TAT
        now_ns = time.time_ns()
        queue_tat_ms = (now_ns - push_time) / 1e6
        
        self.logger.info(f"Processing {task_id} (QueueTAT: {queue_tat_ms:.2f}ms, Mode: {mode})")
        
        # Load data based on mode
        data = b""
        if mode == "PATH":
            # Content is file path
            try:
                file_path = os.path.join(self.settings.scan_mount, content)
                with open(file_path, 'rb') as f:
                    data = f.read()
                os.remove(file_path)  # Cleanup
            except Exception as e:
                self.logger.error(f"File read error: {e}")
                self.redis.rpush(f"result:{task_id}", "ERROR")
                self.redis.expire(f"result:{task_id}", 60)
                return
        else:
            # BODY mode - decode latin1
            data = content.encode('latin1')
        
        # Memory check (if enabled)
        mem_before = self._get_free_memory_mb()
        
        # Scan using INSTREAM
        url = urlparse(self.settings.clamd_url)
        if url.scheme == 'tcp':
            host = url.hostname or 'localhost'
            port = url.port or 3310
            start_time = time.time()
            is_virus, virus_name = self._scan_with_clamav_stream(data, host, port)
            duration = time.time() - start_time
        else:
            # Fallback to file-based scan
            start_time = time.time()
            result, reason = self._scan_file(content if mode == "BODY" else content)
            duration = time.time() - start_time
            is_virus = (result == "infected")
        
        mem_after = self._get_free_memory_mb()
        mem_delta = mem_before - mem_after if mem_before != float('inf') else 0
        
        total_tat_ms = (time.time_ns() - push_time) / 1e6
        
        self.logger.info(f"Scan complete {task_id}: Duration={duration*1000:.2f}ms, TotalTAT={total_tat_ms:.2f}ms, MemDelta={mem_delta:.0f}MB")
        
        # Record TAT statistics
        stat_key = "tat_priority_last" if queue_name == "scan_priority" else "tat_normal_last"
        self.redis.set(stat_key, f"{total_tat_ms:.2f}")
        
        # Push result
        status = "INFECTED" if is_virus else "CLEAN"
        self.redis.rpush(f"result:{task_id}", status)
        self.redis.expire(f"result:{task_id}", 60)

    def _process_task_legacy_format(self, task_json: str, queue_name: str):
        """Process task in legacy JSON format for backward compatibility"""
        try:
            task = json.loads(task_json)
            task_id = task.get("id", "unknown")
            file_path = task.get("file_path")
            tenant_id = task.get("tenant_id", "default")
            
            if not file_path:
                self.logger.error("Task missing file_path")
                return
            
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

    def run(self):
        memory_check_status = "enabled" if self.settings.enable_memory_check else "disabled"
        self.logger.info(f"Starting Virus Scanner Handler (Redis: {self.settings.redis_host}, Clamd: {self.settings.clamd_url}, MemoryCheck: {memory_check_status})")
        
        try:
            self.redis.ping()
        except Exception as e:
            self.logger.critical(f"Could not connect to Redis: {e}")
            return

        while True:
            try:
                # Memory check before polling (if enabled)
                if self.settings.enable_memory_check:
                    free_mem = self._get_free_memory_mb()
                    if free_mem < self.settings.min_free_memory_mb:
                        self.logger.warning(f"Low memory ({free_mem:.0f}MB < {self.settings.min_free_memory_mb}MB), waiting...")
                        time.sleep(5)
                        continue
                
                task_data_raw = self.redis.blpop(self.settings.queues, timeout=5)
                
                if not task_data_raw:
                    continue
                
                queue_name, task_data = task_data_raw
                self.logger.info(f"Received task from {queue_name}")
                
                # Detect format: new format has "|" separator
                if "|" in task_data:
                    self._process_task_new_format(task_data, queue_name)
                else:
                    self._process_task_legacy_format(task_data, queue_name)
                    
            except redis.ConnectionError:
                self.logger.error("Redis connection lost. Retrying in 5 seconds...")
                time.sleep(5)
            except Exception as e:
                self.logger.exception(f"Unexpected error in main loop: {e}")
                time.sleep(1)
