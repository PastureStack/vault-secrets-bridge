FROM golang:1.26-bookworm AS build

ARG VERSION=dev
WORKDIR /src
COPY . .
RUN go test -count=1 ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/vault-secrets-bridge \
    ./cmd/vault-secrets-bridge

FROM ubuntu:26.04

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="PastureStack Vault Secrets Bridge" \
      org.opencontainers.image.description="Host-authenticated broker for short-lived response-wrapped Vault leases" \
      org.opencontainers.image.source="https://github.com/PastureStack/vault-secrets-bridge" \
      org.opencontainers.image.documentation="https://github.com/PastureStack/vault-secrets-bridge/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && groupadd --gid 65532 pasturestack \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin pasturestack \
    && install -d -o 65532 -g 65532 -m 0700 /var/lib/pasturestack/vault-secrets-bridge \
    && rm -f /usr/bin/pebble \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/vault-secrets-bridge /usr/local/bin/vault-secrets-bridge

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vault-secrets-bridge"]
CMD ["serve"]
