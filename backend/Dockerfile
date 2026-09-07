# ---- build ----------------------------------------------------------------
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
COPY . .

# `go build` is left to fetch what it needs rather than running `go mod
# download` first. The module graph includes test-only dependencies -- the
# Docker client that testcontainers drives, and its transitive tree -- which
# the server never imports; downloading the whole graph made this by far the
# slowest step in the build.
#
# CGO is off so the result is a static binary. The migrations are embedded in
# it, so the runtime image needs no source tree.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" \
      -o /out/api ./cmd/api

# ---- run ------------------------------------------------------------------
FROM alpine:3.20

# ca-certificates is needed if the database connection ever uses TLS.
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 vaultly

WORKDIR /app
COPY --from=build /out/api /app/api

# Runs unprivileged: this process holds the master key in memory.
USER vaultly

EXPOSE 8080

# The binary probes itself, so the image needs no curl or wget.
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 \
  CMD ["/app/api", "-healthcheck"]

ENTRYPOINT ["/app/api"]
