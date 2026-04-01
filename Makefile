BINARY    := certree
CMD_DIR   := ./cmd/certree
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -s -w -buildid= -X main.version=$(VERSION)
TAGS      := osusergo,netgo
PLATFORMS := darwin linux windows

.DEFAULT_GOAL := help

.PHONY: build build-snapshot install fmt fmt-fix tidy vet lint test test-ci test-coverage bench bench-profile check clean help

## build: Build the binary
build:
	CGO_ENABLED=0 \
	go build \
	-trimpath \
	-ldflags '$(LDFLAGS)' \
	-tags '$(TAGS)' \
	-o $(BINARY) $(CMD_DIR)

## build-snapshot: Build with goreleaser --snapshot
build-snapshot: clean
	goreleaser build --auto-snapshot

## install: Install the binary via go install
install:
	go install \
	-trimpath \
	-ldflags '$(LDFLAGS)' \
	-tags '$(TAGS)' \
	$(CMD_DIR)

## fmt: Check formatting (fails on diff)
fmt:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted files:"; echo "$$unformatted"; exit 1; \
	fi

## fmt-fix: Fix Go formatting (destructive)
fmt-fix:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Fixing unformatted files..."; \
		gofmt -s -w .; \
	fi

## tidy: Check that go.mod and go.sum are tidy
tidy:
	go mod tidy -diff

## vet: Run go vet (all platforms)
vet:
	@$(foreach os,$(PLATFORMS),GOOS=$(os) go vet ./... &&) true

## lint: Run golangci-lint (all platforms)
lint:
	@$(foreach os,$(PLATFORMS),GOOS=$(os) golangci-lint run ./... &&) true

## test: Run tests (short mode, race, 2m timeout) and compile-check all platforms
test:
	go test -race -short -timeout 2m ./...
	@$(foreach os,$(PLATFORMS),GOOS=$(os) go test -c -o /dev/null ./... &&) true

## test-ci: Run tests (full, race, 5m timeout)
test-ci:
	go test -race -timeout 5m ./...

## test-coverage: Run tests with coverage report
test-coverage:
	go test -race -timeout 5m -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out

## bench: Run all benchmarks
bench:
	go test -bench=. -benchmem -run='NOMATCH' -timeout 5m ./...

## bench-profile: Run benchmarks with CPU and memory profiles
bench-profile:
	go test -bench=. -benchmem -run='NOMATCH' -cpuprofile=cpu-certree.prof -memprofile=mem-certree.prof -timeout 5m ./pkg/certree/
	go test -bench=. -benchmem -run='NOMATCH' -cpuprofile=cpu-render.prof -memprofile=mem-render.prof -timeout 5m ./internal/render/
	go test -bench=. -benchmem -run='NOMATCH' -cpuprofile=cpu-cli.prof -memprofile=mem-cli.prof -timeout 5m ./internal/cli/

## check: Run all quality gates (fmt tidy vet lint test)
check: fmt tidy vet lint test

## clean: Remove build artifacts
clean:
	rm -f $(BINARY) coverage.out cpu.prof mem.prof cpu-*.prof mem-*.prof
	rm -rf ./dist

## help: Show this help
help:
	@echo "certree Makefile"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | column -t -s ':'
