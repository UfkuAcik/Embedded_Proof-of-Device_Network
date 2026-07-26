.PHONY: all check fmt test rust python web arduino secrets

PYTHON ?= python
ARDUINO_CLI ?= arduino-cli

all: check

check: fmt test secrets

fmt:
	cargo fmt --all -- --check

test: rust python web

rust:
	cargo test --workspace
	cargo clippy --workspace --all-targets -- -D warnings

python:
	$(PYTHON) -m pip install -e "./provisioning[test]" -e "./gateway" -e "./indexer[test]"
	$(PYTHON) -m pytest -q provisioning/tests gateway/tests indexer/tests scripts/tests

web:
	cd dashboard && npm test
	cd dashboard && npm run build

arduino:
	$(ARDUINO_CLI) compile --fqbn esp32:esp32:esp32 --libraries arduino/libraries arduino/examples/SecurityDiagnostic
	$(ARDUINO_CLI) compile --fqbn esp32:esp32:esp32 --libraries arduino/libraries arduino/examples/WiFiMiner

secrets:
	$(PYTHON) scripts/check-secrets.py
