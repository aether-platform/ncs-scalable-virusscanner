#!/bin/bash
# Generate Envoy protobuf files for ext_proc

set -e

PROTO_DIR="./protos"
OUT_DIR="./src/virus_scanner/producer"

# Create directories
mkdir -p $PROTO_DIR
mkdir -p $OUT_DIR

# Function to clone and copy if not exists
function fetch_proto_repo() {
    local repo_url=$1
    local src_path=$2
    local dest_path=$3
    local repo_name=$(basename $repo_url .git)
    
    if [ ! -d "$dest_path" ]; then
        echo "Fetching $repo_name ($src_path)..."
        local tmp_dir="/tmp/$repo_name"
        rm -rf "$tmp_dir"
        git clone --depth 1 "$repo_url" "$tmp_dir"
        mkdir -p "$(dirname "$dest_path")"
        if [ -d "$tmp_dir/$src_path" ] || [ -f "$tmp_dir/$src_path" ]; then
            cp -r "$tmp_dir/$src_path" "$dest_path"
        else
            echo "Warning: $src_path not found in $repo_name"
        fi
        rm -rf "$tmp_dir"
    fi
}

# Fetch necessary API components
fetch_proto_repo "https://github.com/envoyproxy/envoy.git" "api/envoy" "$PROTO_DIR/envoy"
fetch_proto_repo "https://github.com/cncf/xds.git" "udpa" "$PROTO_DIR/udpa"
fetch_proto_repo "https://github.com/cncf/xds.git" "xds" "$PROTO_DIR/xds"
fetch_proto_repo "https://github.com/bufbuild/protoc-gen-validate.git" "validate" "$PROTO_DIR/validate"
fetch_proto_repo "https://github.com/googleapis/googleapis.git" "google/rpc" "$PROTO_DIR/google/rpc"
fetch_proto_repo "https://github.com/googleapis/googleapis.git" "google/api" "$PROTO_DIR/google/api"

# Generate Python code
echo "Generating Python protobuf code..."

# Define more comprehensive set of protos
PROTOS_TO_GENERATE=(
    "$PROTO_DIR/envoy/service/ext_proc/v3/external_processor.proto"
    "$PROTO_DIR/envoy/config/core/v3/base.proto"
    "$PROTO_DIR/envoy/config/core/v3/address.proto"
    "$PROTO_DIR/envoy/config/core/v3/backoff.proto"
    "$PROTO_DIR/envoy/config/core/v3/http_uri.proto"
    "$PROTO_DIR/envoy/config/core/v3/extension.proto"
    "$PROTO_DIR/envoy/config/core/v3/socket_option.proto"
    "$PROTO_DIR/envoy/type/v3/http_status.proto"
    "$PROTO_DIR/envoy/type/v3/percent.proto"
    "$PROTO_DIR/envoy/type/v3/semantic_version.proto"
    "$PROTO_DIR/envoy/extensions/filters/http/ext_proc/v3/processing_mode.proto"
    "$PROTO_DIR/envoy/annotations/deprecation.proto"
    "$PROTO_DIR/udpa/annotations/migrate.proto"
    "$PROTO_DIR/udpa/annotations/status.proto"
    "$PROTO_DIR/udpa/annotations/versioning.proto"
    "$PROTO_DIR/xds/annotations/v3/status.proto"
    "$PROTO_DIR/xds/core/v3/context_params.proto"
    "$PROTO_DIR/validate/validate.proto"
)

# Generate everything in one go
uv run python -m grpc_tools.protoc \
    -I$PROTO_DIR \
    --python_out=$OUT_DIR \
    --grpc_python_out=$OUT_DIR \
    ${PROTOS_TO_GENERATE[@]}

# Touch __init__.py in all subdirectories of OUT_DIR to make them packages
find $OUT_DIR -type d -exec touch {}/__init__.py \;

# Remove google directory if it was accidentally generated
rm -rf "$OUT_DIR/google"

echo "Proto generation complete!"
