# syntax=docker/dockerfile:1

# Build metadata, injected by the release pipeline (or `docker build --build-arg`).
ARG VERSION=v0.1.0
ARG COMMIT=dev
ARG BUILDTIME=unknown

# ---- Stage 1: build the React frontend ----
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---- Stage 2: build the Go backend (cloudflared managed as a subprocess) ----
# go.mod requires go 1.27; govulncheck reports 0 vulnerabilities against
# 1.27.0. Keep in sync with the go-version pins in .github/workflows/.
FROM golang:1.27.0-alpine AS gobuild
ARG VERSION
ARG COMMIT
ARG BUILDTIME
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w \
    -X github.com/eoghan2t9/Irongrid-DNS/internal/version.Version=${VERSION} \
    -X github.com/eoghan2t9/Irongrid-DNS/internal/version.Commit=${COMMIT} \
    -X github.com/eoghan2t9/Irongrid-DNS/internal/version.BuildTime=${BUILDTIME}" \
    -o /out/irongrid ./cmd/irongrid

# ---- Stage 3: minimal runtime ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 irongrid && \
    mkdir -p /data/lists /data/certs && chown -R irongrid /data
USER irongrid
WORKDIR /app
COPY --from=gobuild /out/irongrid /app/irongrid
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 443/tcp 8080/tcp
ENTRYPOINT ["/app/irongrid"]
CMD ["-config", "/app/irongrid.yaml", "-data", "/data"]
