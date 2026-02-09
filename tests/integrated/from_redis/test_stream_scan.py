import json
import time
import uuid

import redis


def test_stream_scan_integrated():
    # Configuration
    REDIS_HOST = "localhost"
    REDIS_PORT = 6379

    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=False)

    task_id = str(uuid.uuid4())
    chunks_key = f"chunks:{task_id}"
    done_key = f"{chunks_key}:done"
    result_key = f"result:{task_id}"

    # Clean up any potential stale keys
    r.delete(chunks_key, done_key, result_key)

    print("--- Starting Integrated STREAM Scan Test ---")
    print(f"Task ID: {task_id}")

    # 1. Enqueue task (In a real scenario, producer does this)
    # Format: taskID|MODE|TIMESTAMP|CONTENT(chunks_key)
    push_time = time.time_ns()
    task_str = f"{task_id}|STREAM|{push_time}|{chunks_key}"

    print("Injecting task into scan_normal...")
    r.lpush("scan_normal", task_str)

    # 2. Simulate Producer streaming data (EICAR)
    eicar_string = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    # Split into chunks to test follower behavior
    chunks = [eicar_string[i : i + 10] for i in range(0, len(eicar_string), 10)]

    print(f"Streaming {len(chunks)} chunks to {chunks_key}...")
    for i, chunk in enumerate(chunks):
        r.rpush(chunks_key, chunk)
        # Add a small delay to simulate network/upload latency if desired
        # time.sleep(0.1)

    # 3. Signal completion
    print(f"Signaling completion via {done_key}...")
    r.set(done_key, "1")

    # 4. Wait for result
    print(f"Waiting for result on {result_key} (timeout=10s)...")
    res = r.brpop(result_key, timeout=10)

    assert res, "Timeout waiting for result. Is the consumer running?"

    _, result_json = res
    result = json.loads(result_json.decode("utf-8"))

    print("-" * 30)
    print("RESULT RECEIVED:")
    print(json.dumps(result, indent=2))
    print("-" * 30)

    assert result.get("status") == "INFECTED", (
        f"Unexpected result status: {result.get('status')}"
    )
    assert "EICAR" in result.get("virus", "").upper(), (
        f"Unexpected virus name: {result.get('virus')}"
    )
    print("SUCCESS: Virus correctly detected in STREAM mode!")


if __name__ == "__main__":
    test_stream_scan_integrated()
