# syntax=docker/dockerfile:1
# fallbck-ctl: admin CLI. Authenticate with FALLBCK_API_KEY (created in the Web UI).

# ---- Build stage -------------------------------------------------------------
FROM golang:1.26-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/fallbck-ctl ./cmd/fallbck-ctl

# ---- Runtime stage -----------------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/fallbck-ctl /usr/local/bin/fallbck-ctl

ENV FALLBCK_SERVER_URL=http://fallbck-server:8080

ENTRYPOINT ["/usr/local/bin/fallbck-ctl"]
