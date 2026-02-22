#!/bin/bash

# 1. 設定ファイルの作成 (envoy.yaml)
# SNIを読み取り、dynamic_forward_proxyで名前解決して外へ飛ばす設定
cat <<EOF > envoy.yaml
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 443
    listener_filters:
    - name: "envoy.filters.listener.tls_inspector"
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          http_filters:
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
              dns_cache_config:
                name: dynamic_forward_proxy_cache_config
                dns_lookup_family: V4_ONLY
                dns_refresh_rate: 60s
                host_ttl: 60s
                typed_dns_resolver_config:
                  name: envoy.network.dns_resolver.apple
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.apple.v3.AppleDnsResolverConfig
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  connect_config: {}
                route:
                  cluster: dynamic_forward_proxy_cluster
                  upgrade_configs:
                  - upgrade_type: CONNECT

  clusters:
  - name: dynamic_forward_proxy_cluster
    lb_policy: CLUSTER_PROVIDED
    cluster_type:
      name: envoy.clusters.dynamic_forward_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
        dns_cache_config:
          name: dynamic_forward_proxy_cache_config
          dns_lookup_family: V4_ONLY
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
          validation_context:
            trusted_ca:
              filename: /etc/ssl/certs/ca-certificates.crt
EOF

# 2. Docker Composeファイルの作成
cat <<EOF > docker-compose.yml
services:
  envoy:
    image: envoyproxy/envoy:v1.30-latest
    container_name: envoy-test
    volumes:
      - ./envoy.yaml:/etc/envoy/envoy.yaml
    ports:
      - "443:443"
    dns:
      - 8.8.8.8
    restart: always
EOF

# 3. 起動
docker compose up -d

echo "Envoy setup complete. Testing with curl..."
sleep 3
curl -k --resolve www.google.com:443:127.0.0.1 https://www.google.com -I
