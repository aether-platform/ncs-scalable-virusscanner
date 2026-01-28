import redis
import json
import uuid
import os

def test_virus_scan():
    # Configuration
    REDIS_HOST = 'localhost'
    REDIS_PORT = 6379
    TEST_DATA_DIR = './test-data'
    TEST_FILE_NAME = 'test-file.txt'
    
    # 1. Ensure test-data directory exists
    os.makedirs(TEST_DATA_DIR, exist_ok=True)
    
    # 2. Create a dummy file to scan
    file_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" # EICAR test string
    file_path = os.path.join(TEST_DATA_DIR, TEST_FILE_NAME)
    
    with open(file_path, 'w') as f:
        f.write(file_content)
    
    # Ensure ClamAV (running as different user in container) can read/write it
    os.chmod(file_path, 0o666)
    
    print(f"Created test file at: {file_path}")

    # 3. Inject task into Redis
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    
    task_id = str(uuid.uuid4())
    task = {
        "id": task_id,
        "tenant_id": "test-tenant",
        "file_path": TEST_FILE_NAME # Handler will prepend its SCAN_MOUNT
    }
    
    print(f"Injecting task: {task_id}")
    r.rpush("scan_normal", json.dumps(task))
    
    print("-" * 30)
    print("SUCCESS: Task injected. Check docker-compose logs for scan result.")
    print("Expected result: 'infected' (EICAR test string detected)")
    print("-" * 30)

if __name__ == "__main__":
    test_virus_scan()
