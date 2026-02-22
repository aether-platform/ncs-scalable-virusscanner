# Aether Platform: Intelligent Cache

The `IntelligentCacheService` provides smart bypass and caching logic for the Virus Scanner, specifically optimized for software development workflows.

## Features

- **Priority-based Scanning**: Automatically identifies traffic from trusted development sources to optimize resource allocation (Normal vs. High priority).
  - **Docker Registries**: `get.docker.com`, `registry-1.docker.io`, `quay.io`, `gcr.io`, `ghcr.io`, `registry.k8s.io`
  - **Other Sources**: PyPI, npm, GitHub, Maven.
- **Result Caching**: Caches positive (clean) scan results in Redis.
- **TTL Support**: Default cache expiration is 1 hour (3600 seconds), configurable per entry.

## Integration

The service is used by the `Producer` component to decide whether an incoming request needs to be sent to the virus scanner workers or can be fast-tracked based on the URI's trustworthiness or previous scan history.
