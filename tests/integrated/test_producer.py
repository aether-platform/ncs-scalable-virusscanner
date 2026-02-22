import os
import sys

import grpc
import redis

# Add src to path to import generated protos
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src"))
sys.path.insert(0, src_path)

producer_path = os.path.join(src_path, "aether_platform/virusscan/producer")
sys.path.insert(0, producer_path)

from envoy.config.core.v3 import base_pb2  # noqa: E402
from envoy.service.ext_proc.v3 import external_processor_pb2  # noqa: E402
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc


def test_producer_priority_flow():
    """
    Test the Producer gRPC flow:
    1. Send request headers with X-Priority: high
    2. Send request body
    3. Verify task is in scan_priority queue
    4. Inject result into Redis
    5. Verify gRPC response
    """
    port = os.environ.get("PRODUCER_PORT", "50051")
    channel = grpc.insecure_channel(f"localhost:{port}")
    stub = external_processor_pb2_grpc.ExternalProcessorStub(channel)

    rdb = redis.Redis(host="localhost", port=6379, decode_responses=True)

    # 1. Prepare stream
    def request_generator():
        # Step 1: Headers
        headers = external_processor_pb2.HttpHeaders(
            headers=base_pb2.HeaderMap(
                headers=[
                    base_pb2.HeaderValue(key="x-priority", value="high"),
                    base_pb2.HeaderValue(key="content-type", value="text/plain"),
                ]
            )
        )
        yield external_processor_pb2.ProcessingRequest(request_headers=headers)

        # Step 2: Body
        body = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        yield external_processor_pb2.ProcessingRequest(
            request_body=external_processor_pb2.HttpBody(body=body, end_of_stream=True)
        )

    # 2. Execute gRPC call
    responses = stub.Process(request_generator())

    # Header response
    resp1 = next(responses)
    print("Received header response")
    assert resp1.HasField("request_headers")

    # Body response (This is where the Producer blocks and waits for Redis)
    # We need to simulate the Consumer in the background

    def simulate_consumer():
        print("Waiting for task in scan_priority...")
        task_raw = rdb.brpop("scan_priority", timeout=5)
        if task_raw:
            _, task_str = task_raw
            print(f"Captured task: {task_str}")
            parts = task_str.split("|", 3)
            task_id = parts[0]

            # Inject result
            print(f"Injecting result for {task_id}")
            result_json = '{"status": "INFECTED", "virus": "EICAR detected"}'
            rdb.lpush(f"result:{task_id}", result_json)
            rdb.expire(f"result:{task_id}", 10)
        else:
            print("No task found in scan_priority")

    import threading

    t = threading.Thread(target=simulate_consumer)
    t.start()

    resp2 = next(responses)
    print("Received body response")

    # Verify immediate response (403 for INFECTED)
    assert resp2.HasField("immediate_response")
    assert resp2.immediate_response.status.code == 403
    assert "Virus detected!" in resp2.immediate_response.details

    print("Test passed!")


if __name__ == "__main__":
    test_producer_priority_flow()
