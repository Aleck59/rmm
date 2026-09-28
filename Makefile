# InvMon developer tasks. Run `make help` for the list.
SHELL := bash
PKG := github.com/Aleck59/rmm
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/buildinfo.Version=$(VERSION:v%=%) \
	-X $(PKG)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(PKG)/internal/buildinfo.Date=$(DATE)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: fmt
fmt: ## Format Go code
	gofmt -w .

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

.PHONY: test
test: ## Run tests with the race detector
	go test -race ./...

.PHONY: vulncheck
vulncheck: ## Run govulncheck (informational)
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: web
web: ## Build the SPA into the Go embed directory
	cd web && pnpm install --frozen-lockfile && pnpm build

.PHONY: build
build: ## Build server and agent for the host into bin/
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

.PHONY: run-server
run-server: ## Run the server locally on :8080
	go run ./cmd/invmon-server run --addr :8080

.PHONY: dist
dist: ## Cross-compile and package release artifacts into dist/
	VERSION=$(VERSION:v%=%) bash scripts/build-dist.sh

.PHONY: verify-db
verify-db: ## Run the SQL schema verification (needs a running PostgreSQL)
	psql -X -q -v ON_ERROR_STOP=1 -f docs/db/verify.sql

.PHONY: restore-webui
restore-webui: ## Restore the committed SPA placeholder after a local web build
	rm -rf internal/webui/dist/assets
	git checkout -- internal/webui/dist/index.html

.PHONY: clean
clean: ## Remove build output
	rm -rf bin dist
