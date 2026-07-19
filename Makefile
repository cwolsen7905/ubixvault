# uBix Vault — developer tasks.
# Run `make help` for the list.

BINARY      := ubixvault
PKG         := ./...
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -X main.version=$(VERSION)
GOBIN       := $(shell go env GOPATH)/bin

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the ubixvault binary into ./bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/ubixvault

.PHONY: test
test: ## Run tests with the race detector and coverage
	go test -race -covermode=atomic -coverprofile=coverage.out $(PKG)

.PHONY: cover
cover: test ## Show total test coverage
	@go tool cover -func=coverage.out | tail -1

.PHONY: fmt
fmt: ## Format the code
	gofmt -w .

.PHONY: fmtcheck
fmtcheck: ## Fail if any file is not gofmt-clean
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## Run go vet
	go vet $(PKG)

.PHONY: lint
lint: ## Run golangci-lint (installs it if missing)
	@command -v golangci-lint >/dev/null 2>&1 || \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

.PHONY: vuln
vuln: ## Run govulncheck (installs it if missing)
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck $(PKG)

.PHONY: tidy
tidy: ## Tidy go.mod/go.sum
	go mod tidy

.PHONY: ci
ci: fmtcheck vet test build ## Run the checks CI runs

.PHONY: clean
clean: ## Remove build and coverage artifacts
	rm -rf bin coverage.out
