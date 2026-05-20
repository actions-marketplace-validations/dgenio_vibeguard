.PHONY: help install-dev test lint format-check typecheck ci clean demo bench bench-small bench-medium bench-large update-goldens

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install-dev: ## Install package in editable mode with dev deps
	pip install -e ".[dev]"

test: ## Run tests with coverage
	pytest tests/ -v --cov=vibeguard --cov-report=term-missing --cov-report=xml

lint: ## Run ruff linter
	ruff check vibeguard/ tests/ benchmarks/

format-check: ## Check code formatting with ruff
	ruff format --check vibeguard/ tests/ benchmarks/

typecheck: ## Run mypy type checking
	mypy vibeguard/

ci: lint format-check typecheck test ## Run full CI pipeline locally

clean: ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info .pytest_cache .mypy_cache .coverage htmlcov/ .ruff_cache/ coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

demo: ## Run vibeguard against bundled examples
	vibeguard scan --path examples/vulnerable-node-package
	vibeguard scan --path examples/vulnerable-python-package

bench: bench-small ## Run the default (small) benchmark

bench-small: ## Generate and scan a small synthetic repo (~500 KB)
	python -m benchmarks.run --size small

bench-medium: ## Generate and scan a medium synthetic repo (~5 MB)
	python -m benchmarks.run --size medium

bench-large: ## Generate and scan a large synthetic repo (~20 MB)
	python -m benchmarks.run --size large

update-goldens: ## Regenerate golden reporter snapshots in tests/fixtures/golden/
	PYTEST_UPDATE_GOLDENS=1 pytest tests/test_reporters_golden.py -q
