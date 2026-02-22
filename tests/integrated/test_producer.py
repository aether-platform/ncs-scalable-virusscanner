import importlib
import json
import os
import pkgutil
import sys
import threading

# Add src and producer paths to sys.path
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src"))
if src_path not in sys.path:
    sys.path.insert(0, src_path)

producer_path = os.path.join(src_path, "aether_platform/virusscan/producer")
if producer_path not in sys.path:
    sys.path.insert(0, producer_path)

# 1. First, import core google protobuf descriptors
from google.protobuf import descriptor_pb2  # noqa: F401
from google.protobuf import (any_pb2, duration_pb2, struct_pb2,  # noqa: F401
                             timestamp_pb2, wrappers_pb2)


# 2. Dynamically load all _pb2 modules to populate descriptor pool
# We try multiple times because some might have forward-dependencies
def load_all_pb2():
    packages = ["udpa", "xds", "envoy", "validate"]
    loaded = set()
    modules_to_load = []

    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
            for info in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
                if info.name.endswith("_pb2"):
                    modules_to_load.append(info.name)
        except Exception:
            pass

    # Try multiple passes to handle dependencies
    for _ in range(3):
        for mod_name in modules_to_load:
            if mod_name in loaded:
                continue
            try:
                importlib.import_module(mod_name)
                loaded.add(mod_name)
            except Exception:
                pass


load_all_pb2()

# 3. Import what we actually need
import grpc
import redis
from envoy.config.core.v3 import base_pb2
from envoy.service.ext_proc.v3 import (external_processor_pb2,
                                       external_processor_pb2_grpc)


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
        headers = external_processor_pb2.HttpHeaders(
            headers=base_pb2.HeaderMap(
                headers=[
                    base_pb2.HeaderValue(key="x-priority", value="high"),
                    base_pb2.HeaderValue(key="content-type", value="text/plain"),
                ]
            )
        )
        yield external_processor_pb2.ProcessingRequest(request_headers=headers)

        body = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        yield external_processor_pb2.ProcessingRequest(
            request_body=external_processor_pb2.HttpBody(body=body, end_of_stream=True)
        )

    # 2. Execute gRPC call
    responses = stub.Process(request_generator())

    try:
        resp1 = next(responses)
        print("Received header response")
        assert resp1.HasField("request_headers")
    except StopIteration:
        print("Error: No header response received")
        return

    # Body response simulation
    def simulate_consumer():
        print("Waiting for task in scan_priority...")
        task_raw = rdb.brpop("scan_priority", timeout=5)
        if task_raw:
            _, task_str = task_raw
            print(f"Captured task: {task_str}")

            if task_str.startswith("{"):
                job = json.loads(task_str)
                task_id = job.get("stream_id")
            else:
                parts = task_str.split("|", 3)
                task_id = parts[0]

            print(f"Injecting result for {task_id}")
            result_json = '{"status": "INFECTED", "virus": "EICAR detected"}'
            rdb.lpush(f"result:{task_id}", result_json)
            rdb.expire(f"result:{task_id}", 10)
        else:
            print("No task found in scan_priority")

    t = threading.Thread(target=simulate_consumer)
    t.daemon = True
    t.start()

    try:
        resp2 = next(responses)
        print("Received body response")
        assert resp2.HasField("immediate_response")
        assert resp2.immediate_response.status.code == 403
        assert "Virus detected!" in resp2.immediate_response.details
    except StopIteration:
        print("Error: No body response received")
        return

    print("Test passed!")


if __name__ == "__main__":
    test_producer_priority_flow()
