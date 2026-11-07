PYTHON ?= python3
CLANG_FORMAT ?= clang-format
YAPF ?= yapf
.PHONY: test test-native

test:
	$(PYTHON) -m pytest -q tests tests_release

test-native:
	$(PYTHON) -m pytest -q tests tests_release tests_integration

.PHONY: format format-check test-coverage

# Google-based C++ style with 4-space indentation; use native clang-format.
# Never format Git submodules under external/.
format:
	$(CLANG_FORMAT) -i scanner/src/*.cc scanner/fuzz/*.cc scanner/include/vulnimprint/*.h
	$(YAPF) --style=.style.yapf -ir cli.py factory scripts tools tests tests_release tests_integration

format-check:
	$(CLANG_FORMAT) --dry-run --Werror scanner/src/*.cc scanner/fuzz/*.cc scanner/include/vulnimprint/*.h
	@set -eu; tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	 $(YAPF) --style=.style.yapf -dr cli.py factory scripts tools tests tests_release tests_integration > "$$tmp"; \
	 if test -s "$$tmp"; then cat "$$tmp"; exit 1; fi

test-coverage:
	python -m coverage erase
	python -m coverage run -m pytest -q tests tests_release
	python -m coverage report --include='factory/*.py,tools/*.py'
	python -m coverage json -o coverage.json
