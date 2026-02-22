# Envoy Interception Example

This directory contains an example configuration for an **Interception Proxy** using Envoy, featuring DNS-based steering and Dynamic Forward Proxy.

## Contents

- `envoy.yaml`: Envoy configuration for TLS inspection and dynamic forward proxy.
- `docker-compose.yaml`: Setup for running the Envoy interception test environment.
- `setup.sh`: Script to initialize the environment and perform a connectivity test.
- `test_stack.sh`: Script for verifying the interceptor stack.

## Architecture Highlights

1. **DNS-based Steering**: Client traffic is directed to Envoy via DNS poisoning or resolve overrides (demonstrated in `setup.sh` via `curl --resolve`).
2. **TLS Inspection (SSL Bump)**: Envoy's `TlsInspector` and `UpstreamTlsContext` are used to handle encrypted traffic.
3. **Dynamic Forward Proxy**: Uses `envoy.filters.http.dynamic_forward_proxy` to resolve and forward traffic to original destinations based on SNI/Host headers.

## Origin

These files were migrated from `/tmp/envoy-test` to preserve the architectural demonstration of the NCS Interception Proxy capabilities.
