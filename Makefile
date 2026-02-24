.PHONY: release release-quick test-local test-docker

IMAGE_NAME := ncs-scalable-virusscanner-consumer
GHCR_IMAGE := ghcr.io/aether-platform/$(IMAGE_NAME)
INTERNAL_IMAGE := registry.aether.internal/aether-platform/$(IMAGE_NAME)
TAG := latest

# General build targets
build: build-consumer build-producer

build-consumer:
	@docker buildx build --platform linux/amd64 \
		--builder aether-builder \
		--build-arg FLAVOR=consumer \
		-t registry.aether.internal/aether-platform/ncs-scalable-virusscanner-consumer:$(TAG) \
		-t ghcr.io/aether-platform/ncs-scalable-virusscanner-consumer:$(TAG) \
		.\
		--output type=docker

build-producer:
	@docker buildx build --platform linux/amd64 \
		--builder aether-builder \
		--build-arg FLAVOR=producer \
		-t registry.aether.internal/aether-platform/ncs-scalable-virusscanner-producer:$(TAG) \
		-t ghcr.io/aether-platform/ncs-scalable-virusscanner-producer:$(TAG) \
		.\
		--output type=docker


# Release targets (Multi-arch)
release: release-consumer release-producer

release-consumer:
	@echo "Building and pushing consumer (amd64/arm64):$(TAG)..."
	@docker buildx build --platform linux/amd64,linux/arm64 \
		--builder aether-builder \
		--build-arg FLAVOR=consumer \
		-t registry.aether.internal/aether-platform/ncs-scalable-virusscanner-consumer:$(TAG) \
		-t ghcr.io/aether-platform/ncs-scalable-virusscanner-consumer:$(TAG) \
		--push \
		. \
		--output type=registry,push=true,oci=false

release-producer:
	@echo "Building and pushing producer (amd64/arm64):$(TAG)..."
	@docker buildx build --platform linux/amd64,linux/arm64 \
		--builder aether-builder \
		--build-arg FLAVOR=producer \
		-t registry.aether.internal/aether-platform/ncs-scalable-virusscanner-producer:$(TAG) \
		-t ghcr.io/aether-platform/ncs-scalable-virusscanner-producer:$(TAG) \
		--push \
		. \
		--output type=registry,push=true,oci=false

# Quick release (AMD64 only)
release-quick: release-quick-consumer release-quick-producer

release-quick-consumer:
	@echo "Building and pushing consumer (quick:amd64 only):$(TAG)..."
	@docker buildx build --platform linux/amd64 \
		--builder aether-builder \
		--build-arg FLAVOR=consumer \
		-t registry.aether.internal/aether-platform/ncs-scalable-virusscanner-consumer:$(TAG) \
		-t ghcr.io/aether-platform/ncs-scalable-virusscanner-consumer:$(TAG) \
		--push \
		. \
		--output type=registry,push=true,oci=false

release-quick-producer:
	@echo "Building and pushing producer (quick:amd64 only):$(TAG)..."
	@docker buildx build --platform linux/amd64 \
		--builder aether-builder \
		--build-arg FLAVOR=producer \
		-t registry.aether.internal/aether-platform/ncs-scalable-virusscanner-producer:$(TAG) \
		-t ghcr.io/aether-platform/ncs-scalable-virusscanner-producer:$(TAG) \
		--push \
		. \
		--output type=registry,push=true,oci=false

# Local integrated tests (requires Redis and ClamAV running)
test-local:
	@echo "Running local integrated tests..."
	export REDIS_HOST=localhost && \
	export CLAMD_URL=tcp://localhost:3310 && \
	export SCAN_MOUNT=/tmp/virusscan && \
	uv run pytest -s tests/integrated/ tests/local/from_consumer/

# Docker-based integrated tests
test-docker:
	@echo "Running Docker-based integrated tests..."
	docker compose up --build --exit-code-from handler
