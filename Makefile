.PHONY: all web build run install test lint vuln docker docker-up release clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.0)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
BUILDTIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/eoghan2t9/Irongrid-DNS/internal/version.Version=$(VERSION) \
	-X github.com/eoghan2t9/Irongrid-DNS/internal/version.Commit=$(COMMIT) \
	-X github.com/eoghan2t9/Irongrid-DNS/internal/version.BuildTime=$(BUILDTIME)

# Builds the frontend and the Go binary (frontend embedded).
all: web build

## web: install deps and build the React dashboard into web/dist
web:
	cd web && npm install --no-audit --no-fund && npm run build

## build: compile the single self-contained binary (uses existing web/dist)
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o irongrid ./cmd/irongrid

## install: run the interactive TUI setup wizard
install: build
	./irongrid install

## run: build and run with a local config
run: build
	./irongrid -config irongrid.yaml -data data

# SHA256SUMS: macOS ships `shasum -a 256` instead of `sha256sum`.
SHA256 := $(shell command -v sha256sum 2>/dev/null || echo 'shasum -a 256')

## release: cross-compile static binaries for Linux/macOS/Windows into dist/
release: web
	rm -rf dist && mkdir -p dist
	@set -e; \
	for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		os=$${t%%/*}; arch=$${t##*/}; \
		ext=$$([ "$$os" = windows ] && echo .exe || echo ''); \
		name=irongrid-$$os-$$arch$$ext; \
		echo "  -> $$name"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/$$name ./cmd/irongrid; \
	done
	cd dist && $(SHA256) irongrid-* > SHA256SUMS.txt
	ls -lh dist

## test: run all Go tests (with the race detector) and vet
test:
	go vet ./...
	go test -race ./...

## lint: run golangci-lint over the Go codebase (pinned, see .golangci.yml)
lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@v2.12.2 run ./...

## vuln: scan the Go dependency tree for known CVEs (golang.org/x/vuln)
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## docker: build the container image
docker:
	docker compose build

## docker-up: run Irongrid DNS + Dragonfly with docker compose
docker-up:
	docker compose up -d --build

clean:
	rm -f irongrid
	rm -rf dist web/dist web/node_modules
