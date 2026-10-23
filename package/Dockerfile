# syntax=docker/dockerfile:1.7
FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build

ARG VERSION=dev
WORKDIR /src
COPY . .
RUN go test -count=1 ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/vault-secrets-bridge \
    ./cmd/vault-secrets-bridge

FROM ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b

ARG VERSION=dev
ARG REVISION=unknown
ARG UBUNTU_SNAPSHOT=20260825T000000Z

ADD --checksum=sha256:5b6326f1932cfd7be57130561dc78192f09ed9f58bfbe6606ed0c50510c3b6cd \
    https://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20260816ubuntu0.26.04.1_all.deb \
    /tmp/ca-certificates.deb
LABEL org.opencontainers.image.title="PastureStack Vault Secrets Bridge" \
      org.opencontainers.image.description="Host-authenticated broker for short-lived response-wrapped Vault leases" \
      org.opencontainers.image.source="https://github.com/PastureStack/vault-secrets-bridge" \
      org.opencontainers.image.documentation="https://github.com/PastureStack/vault-secrets-bridge/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY ubuntu-security-packages.lock /licenses/ubuntu-security-packages.lock
COPY scripts/install-ubuntu-security-updates /usr/local/libexec/pasturestack/install-ubuntu-security-updates
ADD --checksum=sha256:5b6326f1932cfd7be57130561dc78192f09ed9f58bfbe6606ed0c50510c3b6cd https://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20260816ubuntu0.26.04.1_all.deb /opt/pasturestack-ca-certificates.deb
RUN set -eux; \
    mkdir -p /tmp/ca-bootstrap /etc/ssl/certs; \
    dpkg-deb --extract /tmp/ca-certificates.deb /tmp/ca-bootstrap; \
    find /tmp/ca-bootstrap/usr/share/ca-certificates -type f -name '*.crt' | LC_ALL=C sort | while IFS= read -r certificate; do sed -e '$a\' "${certificate}"; done > /etc/ssl/certs/ca-certificates.crt; \
    rm -rf /tmp/ca-bootstrap /tmp/ca-certificates.deb; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; \
    printf 'Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/%s\nSuites: resolute resolute-updates resolute-backports resolute-security\nComponents: main universe restricted multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nSnapshot: no\n' "${UBUNTU_SNAPSHOT}" > /etc/apt/sources.list.d/pasturestack-snapshot.sources; \
    printf 'Acquire::Retries "5";\nAcquire::https::CaInfo "/etc/ssl/certs/ca-certificates.crt";\nAcquire::https::Verify-Peer "true";\nAcquire::https::Verify-Host "true";\nAcquire::AllowInsecureRepositories "false";\nAPT::Get::AllowUnauthenticated "false";\n' > /etc/apt/apt.conf.d/80pasturestack-snapshot; \
    apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && groupadd --gid 65532 pasturestack \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin pasturestack \
    && install -d -o 65532 -g 65532 -m 0700 /var/lib/pasturestack/vault-secrets-bridge \
    && rm -f /usr/bin/pebble \
    && dpkg -i /opt/pasturestack-ca-certificates.deb \
    && update-ca-certificates --fresh \
    && test "$(dpkg-query -W -f='${Version}' ca-certificates)" = '20260816ubuntu0.26.04.1' \
    && test ! -e /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt \
    && rm -f /opt/pasturestack-ca-certificates.deb \
    && sh /usr/local/libexec/pasturestack/install-ubuntu-security-updates /licenses/ubuntu-security-packages.lock /etc/ssl/certs/ca-certificates.crt \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/vault-secrets-bridge /usr/local/bin/vault-secrets-bridge

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vault-secrets-bridge"]
CMD ["serve"]
