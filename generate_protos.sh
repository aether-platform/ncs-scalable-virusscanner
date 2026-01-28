#!/bin/bash
# Generate Envoy protobuf files for ext_proc

set -e

PROTO_DIR="./protos"
OUT_DIR="./src/virus_scanner/producer"

# Create directories
mkdir -p $PROTO_DIR
mkdir -p $OUT_DIR

# Clone Envoy API protos (or use vendored version)
if [ ! -d "$PROTO_DIR/envoy" ]; then
    echo "Downloading Envoy API protos..."
    git clone --depth 1 https://github.com/envoyproxy/envoy.git /tmp/envoy
    cp -r /tmp/envoy/api/envoy $PROTO_DIR/
    rm -rf /tmp/envoy
fi

# Generate Python code
echo "Generating Python protobuf code..."
python -m grpc_tools.protoc \
    -I$PROTO_DIR \
    --python_out=$OUT_DIR \
    --grpc_python_out=$OUT_DIR \
    $PROTO_DIR/envoy/service/ext_proc/v3/*.proto \
    $PROTO_DIR/envoy/config/core/v3/base.proto \
    $PROTO_DIR/envoy/type/v3/http_status.proto

echo "Proto generation complete!"
echo "Generated files are in: $OUT_DIR"
