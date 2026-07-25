#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${VALIDATION_TEMP_BASE:-}" ]]; then
    [[ -d "$VALIDATION_TEMP_BASE" ]]
    validation_tmp="$(mktemp -d "$VALIDATION_TEMP_BASE/vault-secrets-bridge-validation.XXXXXXXX")"
else
    validation_tmp="$(mktemp -d)"
fi

cleanup() {
    if [[ -n "${validation_tmp:-}" && -d "$validation_tmp" && "$validation_tmp" != "/" ]]; then
        rm -rf -- "$validation_tmp"
    fi
}
trap cleanup EXIT

cd "$repo_root"
command -v go >/dev/null
command -v gofmt >/dev/null

export GOTOOLCHAIN=local
export GOWORK=off
export GOPROXY=off
export GOSUMDB=off
export GOCACHE="$validation_tmp/go-build"
export GOMODCACHE="$validation_tmp/go-mod"

unformatted="$(gofmt -l cmd internal)"
if [[ -n "$unformatted" ]]; then
    printf 'gofmt check failed:\n%s\n' "$unformatted" >&2
    exit 1
fi

go test -mod=mod -count=3 ./...
go test -mod=mod -tags=publictree -count=1 ./internal/safety
go vet -mod=mod ./...
go mod verify

module_count="$(go list -mod=mod -m all | wc -l | tr -d '[:space:]')"
if [[ "$module_count" != "1" ]] || [[ "$(go list -mod=mod -m all)" != "github.com/PastureStack/vault-secrets-bridge" ]]; then
    printf 'module dependency gate failed\n' >&2
    exit 1
fi

if command -v gcc >/dev/null 2>&1 && [[ "$(go env CGO_ENABLED)" == "1" ]]; then
    go test -mod=mod -race -count=1 ./...
else
    printf 'SKIP race test: CGO or gcc is unavailable.\n'
fi

build_target() {
    local goos="$1"
    local goarch="$2"
    local output="$3"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -mod=mod -trimpath -buildvcs=false '-ldflags=-s -w' \
        -o "$output" ./cmd/vault-secrets-bridge
}

host_goos="$(go env GOOS)"
host_goarch="$(go env GOARCH)"
host_extension=""
if [[ "$host_goos" == "windows" ]]; then
    host_extension=".exe"
fi
host_a="$validation_tmp/host-a$host_extension"
host_b="$validation_tmp/host-b$host_extension"
windows_binary="$validation_tmp/vault-secrets-bridge-windows-amd64.exe"
linux_binary="$validation_tmp/vault-secrets-bridge-linux-amd64"

build_target "$host_goos" "$host_goarch" "$host_a"
build_target "$host_goos" "$host_goarch" "$host_b"
build_target windows amd64 "$windows_binary"
build_target linux amd64 "$linux_binary"
cmp -s "$host_a" "$host_b"
printf 'Host reproducible SHA-256: %s\n' "$(sha256sum "$host_a" | awk '{print toupper($1)}')"
printf 'Windows amd64 SHA-256: %s\n' "$(sha256sum "$windows_binary" | awk '{print toupper($1)}')"
printf 'Linux amd64 SHA-256: %s\n' "$(sha256sum "$linux_binary" | awk '{print toupper($1)}')"

for binary in "$windows_binary" "$linux_binary"; do
    VAULT_SECRETS_BRIDGE_BINARY="$binary" \
        go test -mod=mod -count=1 -run '^TestExternalBinaryGate$' ./internal/safety
done

request="$(cat <<JSON
{"apiVersion":"pasturestack.io/vault-secrets-bridge/v1alpha1","operation":"issue","requestRef":"sha256:1111111111111111111111111111111111111111111111111111111111111111","subjectRef":"sha256:2222222222222222222222222222222222222222222222222222222222222222","roleRef":"sha256:3333333333333333333333333333333333333333333333333333333333333333","policySetRef":"sha256:4444444444444444444444444444444444444444444444444444444444444444","audienceRef":"sha256:5555555555555555555555555555555555555555555555555555555555555555","idempotencyRef":"sha256:6666666666666666666666666666666666666666666666666666666666666666","lease":{"leaseRef":"sha256:7777777777777777777777777777777777777777777777777777777777777777","currentState":"absent","observedGeneration":0,"expectedGeneration":0,"targetGeneration":1,"renewalCount":0,"policyCount":2,"ttlSeconds":300,"wrapTTLSeconds":60,"renewable":true,"notBefore":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T00:05:00Z"},"assertions":{"subjectAuthenticated":true,"policyAuthorized":true,"issuerAttested":true,"transportProtected":true,"requestFresh":true}}
JSON
)"

capabilities="$($host_a capabilities)"
validated="$(printf '%s' "$request" | "$host_a" validate)"
planned="$(printf '%s' "$request" | "$host_a" --locale zh-TW plan)"

for output in "$capabilities" "$validated" "$planned"; do
    if grep -Fq '1111111111111111111111111111111111111111111111111111111111111111' <<<"$output" || \
        grep -Fq '7777777777777777777777777777777777777777777777777777777777777777' <<<"$output"; then
        printf 'CLI output echoed request metadata\n' >&2
        exit 1
    fi
    grep -Fq '"network":false' <<<"$output"
    grep -Fq '"execution":false' <<<"$output"
done
grep -Fq 'asserted-unverified' <<<"$planned"

printf 'Validation passed.\n'
