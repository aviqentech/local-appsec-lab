.PHONY: test lint check build benchmark
test:
	python -m pytest -q
lint:
	python scripts/sync_resources.py --check
	ruff check src tests installers benchmarks scripts install.py
	ruff format --check src tests installers benchmarks scripts install.py
check: lint test
build:
	python -m build
benchmark:
	python benchmarks/evaluator.py
