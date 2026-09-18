# Sixi Assure Rules — the deterministic engine and its data.
# Everything here runs offline with the Go toolchain and nothing else.
.DEFAULT_GOAL := help
.PHONY: help test eval check lint tidy corpus-inventory

PACKS    ?= packs
POLICY   ?= policy.yaml
MODELS   ?= golden-set/models
EXPECTED ?= golden-set/expected
MODEL    ?= examples/agentic-ai-on-azure-bad-twin.json

help: ## List the targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-18s\033[0m %s\n", $$1, $$2}'

test: ## go vet + the whole test suite (packs load, rules compile, fixtures behave)
	go vet ./...
	go test ./...

eval: ## Golden set: every rule's fixtures, then precision and recall per rule and per pack
	go run ./cmd/assure-eval -packs $(PACKS) -policy $(POLICY) -models $(MODELS) -expected $(EXPECTED)

check: ## Validate one model and print its findings: make check MODEL=path/to/model.json
	go run ./cmd/assure-check -packs $(PACKS) -policy $(POLICY) $(MODEL)

lint: ## gofmt must have nothing to say
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt:"; echo "$$out"; exit 1; fi
	@echo "gofmt clean"

tidy: ## Refresh go.mod / go.sum
	go mod tidy

corpus-inventory: ## Licence inventory of the published corpus (what carries text, what carries references only)
	python3 scripts/redact_corpus.py --dst corpus --inventory-only
