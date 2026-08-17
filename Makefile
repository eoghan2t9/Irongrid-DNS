.PHONY: all web build run install test lint vuln docker docker-up release pgo-profile build-pgo clean bench bench-tcp bench-doh bench-reuseport bench-udp-sockets

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

## pgo-profile: collect a CPU profile from the query-path benchmarks (PGO input)
pgo-profile:
	go test ./internal/dnsserver -run '^$$' \
		-bench 'BenchmarkHandler(UpstreamMiss|CacheHit)$$' -benchtime=20s \
		-cpuprofile pgo.pprof

## build-pgo: build with profile-guided optimization (collects the profile first)
build-pgo: pgo-profile
	CGO_ENABLED=0 go build -trimpath -pgo=pgo.pprof -ldflags "$(LDFLAGS)" -o irongrid ./cmd/irongrid

## install: run the interactive TUI setup wizard
install: build
	./irongrid install

## run: build and run with a local config
run: build
	./irongrid -config irongrid.yaml -data data

# SHA256SUMS: macOS ships `shasum -a 256` instead of `sha256sum`.
SHA256 := $(shell command -v sha256sum 2>/dev/null || echo 'shasum -a 256')

## release: cross-compile static binaries for Linux/macOS/Windows into dist/,
## with profile-guided optimization (PGO profile collected once, reused for
## every target — PGO profiles are symbol-based, so one profile applies
## across GOOS/GOARCH)
release: web pgo-profile
	rm -rf dist && mkdir -p dist
	@set -e; \
	for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		os=$${t%%/*}; arch=$${t##*/}; \
		ext=$$([ "$$os" = windows ] && echo .exe || echo ''); \
		name=irongrid-$$os-$$arch$$ext; \
		echo "  -> $$name"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -pgo=pgo.pprof -ldflags "$(LDFLAGS)" \
			-o dist/$$name ./cmd/irongrid; \
	done
	@set -e; \
	for t in linux/amd64 darwin/amd64 windows/amd64; do \
		os=$${t%%/*}; arch=$${t##*/}; \
		ext=$$([ "$$os" = windows ] && echo .exe || echo ''); \
		name=irongrid-$$os-$$arch-v3$$ext; \
		echo "  -> $$name (GOAMD64=v3 opt-in build for modern x86_64)"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOAMD64=v3 go build -trimpath -pgo=pgo.pprof -ldflags "$(LDFLAGS)" \
			-o dist/$$name ./cmd/irongrid; \
	done
	cd dist && $(SHA256) irongrid-* > SHA256SUMS.txt
	ls -lh dist

## test: run all Go tests (with the race detector) and vet
test:
	go vet ./...
	go test -race ./...

## lint: run golangci-lint over the Go codebase (pinned version below; not a
## go.mod tool directive — golangci-lint's own dependency tree is large
## enough that pulling it into this module's go.sum roughly triples it, and
## CI installs it independently via golangci-lint-action anyway)
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run ./...

## vuln: scan the Go dependency tree for known CVEs (golang.org/x/vuln, pinned
## via the go.mod tool directive)
vuln:
	go tool govulncheck ./...

## bench: load-test a running server over UDP (see bench/dnsload)
bench:
	go run ./bench/dnsload -addr 127.0.0.1:53 -proto udp

## bench-tcp: load-test a running server over TCP
bench-tcp:
	go run ./bench/dnsload -addr 127.0.0.1:53 -proto tcp

## bench-doh: load-test a running server over DoH
bench-doh:
	go run ./bench/dnsload -addr 127.0.0.1:53 -proto doh

## bench-reuseport: compare 1 vs 8 SO_REUSEPORT sockets on loopback
bench-reuseport:
	go run ./bench/reuseport -sockets 1 -dur 5s
	go run ./bench/reuseport -sockets 8 -dur 5s

## bench-udp-sockets: DNS qps with 1 vs 8 UDP sockets (in-process, real listen path)
bench-udp-sockets:
	go run ./bench/udpsockets -dur 5s

## docker: build the container image
docker:
	docker compose build

## docker-up: run Irongrid DNS + Dragonfly with docker compose
docker-up:
	docker compose up -d --build

clean:
	rm -f irongrid
	rm -rf dist web/dist web/node_modules
