.PHONY: release release-quick test-local test-docker

IMAGE_NAME := ncs-scalable-virusscanner-consumer
GHCR_IMAGE := ghcr.io/aether-platform/$(IMAGE_NAME)
INTERNAL_IMAGE := registry.aether.internal/aether-platform/$(IMAGE_NAME)
TAG := latest

build:
	docker buildx build --platform linux/amd64 \
		--builder aether-builder \
		-t $(INTERNAL_IMAGE):$(TAG) \
		-t $(GHCR_IMAGE):$(TAG) \
		.\
		--output type=docker


release:
	@echo "Building and pushing $(IMAGE_NAME):$(TAG)..."
	docker buildx build --platform linux/amd64 \
		--builder aether-builder \
		-t $(INTERNAL_IMAGE):$(TAG) \
		-t $(GHCR_IMAGE):$(TAG) \
		--push \
		. \
				--output type=registry,push=true,oci=false

	@echo "✅ Pushed to ghcr.io and registry.aether.internal"

# Alias for consistency with other images
release-quick: release

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
