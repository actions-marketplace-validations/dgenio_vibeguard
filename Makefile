.PHONY: help install-dev test lint format-check typecheck ci clean demo

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install-dev: ## Install package in editable mode with dev deps
	pip install -e ".[dev]"

test: ## Run tests with coverage
	pytest tests/ -v --cov=vibeguard --cov-report=term-missing

lint: ## Run ruff linter
	ruff check vibeguard/ tests/

format-check: ## Check code formatting with ruff
	ruff format --check vibeguard/ tests/

typecheck: ## Run mypy type checking
	mypy vibeguard/

ci: lint format-check typecheck test ## Run full CI pipeline locally

clean: ## Remove build artifacts
	rm -rf dist/ build/ *.egg-info .pytest_cache .mypy_cache .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

demo: ## Run vibeguard against bundled examples
	vibeguard scan --path examples/vulnerable-node-package
	vibeguard scan --path examples/vulnerable-python-package
