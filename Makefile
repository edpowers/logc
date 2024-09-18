.PHONY: test lint check

# Explicitly set the path to Poetry
POETRY := /opt/homebrew/bin/poetry

# Define a helper function to run commands in the virtual environment
define run-in-venv
	$(POETRY) run $(1)
endef

test:
	$(call run-in-venv, pytest --cov=logc --cov-report=term-missing --cov-fail-under=99)

lint:
	$(call run-in-venv, ruff check .)

check: test lint
