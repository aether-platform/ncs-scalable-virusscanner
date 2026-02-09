.PHONY: release test-local test-docker

# Release to main (triggers nightly build)
release:
	@echo "Releasing nightly build to main..."
	git push origin main

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
