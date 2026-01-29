.PHONY: release

release:
	@echo "Releasing nightly build..."
	git tag -f nightly
	git push -f origin nightly
