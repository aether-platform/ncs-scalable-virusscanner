import os
import time
import uuid

import redis


def test_virus_scan():
    # Configuration
    REDIS_HOST = "localhost"
    REDIS_PORT = 6379
    TEST_DATA_DIR = "./test-data"
    TEST_FILE_NAME = "test-file.txt"

    # 1. Ensure test-data directory exists
    os.makedirs(TEST_DATA_DIR, exist_ok=True)

    # 2. Create a dummy file to scan
    # EICAR test string
    file_content = (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    file_path = os.path.join(TEST_DATA_DIR, TEST_FILE_NAME)

    with open(file_path, "w") as f:
        f.write(file_content)

    # Ensure ClamAV (running as different user in container) can read/write it
    os.chmod(file_path, 0o666)

    print(f"Created test file at: {file_path}")

    # 3. Inject task into Redis using the new pipe-separated format
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    task_id = str(uuid.uuid4())
    push_time = int(time.time_ns())
    # Format: taskID|MODE|TIMESTAMP|CONTENT
    task_str = f"{task_id}|PATH|{push_time}|{TEST_FILE_NAME}"

    print(f"Injecting task: {task_id}")
    r.rpush("scan_normal", task_str)

    print("-" * 30)
    print("SUCCESS: Task injected. Check logs for scan result.")
    print("Expected result: 'infected' (EICAR test string detected)")
    print("-" * 30)


if __name__ == "__main__":
    test_virus_scan()
