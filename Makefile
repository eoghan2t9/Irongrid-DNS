.PHONY: all web build run install test vet docker docker-up clean

# Builds the frontend and the Go binary (frontend embedded).
all: web build

## web: install deps and build the React dashboard into web/dist
web:
	cd web && npm install --no-audit --no-fund && npm run build

## build: compile the single self-contained binary
build:
	go build -trimpath -o irongrid ./cmd/irongrid

## install: run the interactive TUI setup wizard
install: build
	./irongrid install

## run: build and run with a local config
run: build
	./irongrid -config irongrid.yaml -data data

## test: run all Go tests and vet
test:
	go vet ./...
	go test ./...

## docker: build the container image
docker:
	docker compose build

## docker-up: run Irongrid DNS + Dragonfly with docker compose
docker-up:
	docker compose up -d --build

clean:
	rm -f irongrid
	rm -rf web/dist web/node_modules
