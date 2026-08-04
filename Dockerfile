# syntax=docker/dockerfile:1

# ---- Stage 1: build the React frontend ----
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---- Stage 2: build the Go backend (cloudflared baked in) ----
FROM golang:1.22-alpine AS gobuild
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
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
