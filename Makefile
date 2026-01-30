.PHONY: release

release:
	@echo "Releasing nightly build to main..."
	git push origin main
