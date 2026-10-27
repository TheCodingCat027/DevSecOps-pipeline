#!/usr/bin/env bash
# stages/sca/install.sh — ensure the PINNED Trivy binary is available.
#
# Prints the absolute path of the trivy binary on STDOUT (and nothing else).
# All diagnostics go to STDERR.  Idempotent: a second call is a cheap no-op.
#
# Cache layout (document in README so CI can cache it):
#   ${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-<version>/trivy
#
# (The vulnerability DATABASE is a separate cache, managed by run.sh:
#   ${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-db/)
#
# Environment knobs (all optional):
#   TRIVY_BIN                Use this binary instead of installing (tests / air-gapped use).
#                            It must exist and be executable; no version check is done.
#   TRIVY_DOWNLOAD_BASE      Base URL holding the release assets (default: official GitHub
#                            release for the pinned version).  Use for an internal mirror.
#   TRIVY_VERIFY_OFFICIAL    1 (default) = also cross-check the archive against the official
#                            trivy_<version>_checksums.txt published in the release.
#                            The pinned checksum below is ALWAYS enforced.
#   XDG_CACHE_HOME           Relocates the cache.
#
# Exit: 0 ok, 1 install failed.

set -euo pipefail

TRIVY_VERSION="0.76.1"

# SHA-256 of the release archives, copied from the project's official
# trivy_0.76.1_checksums.txt (https://github.com/aquasecurity/trivy/releases/tag/v0.76.1).
declare -A PINNED_SHA256=(
    [Linux-64bit]="c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"
    [Linux-ARM64]="e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f"
    [macOS-64bit]="7aa762eacd582052d053b62dcf972a1ab058abe39a57ccae234ed8894945b6b7"
    [macOS-ARM64]="11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5"
)

log() { echo "[sca:install] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# --- test / mirror override ---------------------------------------------------
if [[ -n "${TRIVY_BIN:-}" ]]; then
    [[ -x "$TRIVY_BIN" ]] || die "TRIVY_BIN is set but not executable: $TRIVY_BIN"
    echo "$TRIVY_BIN"
    exit 0
fi

CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops"
INSTALL_DIR="$CACHE_ROOT/trivy-$TRIVY_VERSION"
BIN="$INSTALL_DIR/trivy"

reported_version() { # prints the bare version a trivy binary reports ("0.76.1")
    "$1" --version 2>/dev/null | awk '/^Version:/ {print $2; exit}'
}

# --- already installed? -------------------------------------------------------
if [[ -x "$BIN" ]]; then
    if [[ "$(reported_version "$BIN" || true)" == "$TRIVY_VERSION" ]]; then
        echo "$BIN"
        exit 0
    fi
    log "cached binary has the wrong version; reinstalling"
fi

# --- platform detection -------------------------------------------------------
case "$(uname -s)" in
    Linux)  OS="Linux" ;;
    Darwin) OS="macOS" ;;
    *) die "unsupported OS: $(uname -s)" ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  ARCH="64bit" ;;
    aarch64|arm64) ARCH="ARM64" ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
esac
PLATFORM="${OS}-${ARCH}"
EXPECTED_SHA="${PINNED_SHA256[$PLATFORM]:-}"
[[ -n "$EXPECTED_SHA" ]] || die "no pinned checksum for platform $PLATFORM"

ASSET="trivy_${TRIVY_VERSION}_${PLATFORM}.tar.gz"
BASE="${TRIVY_DOWNLOAD_BASE:-https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}}"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    else die "neither sha256sum nor shasum is available"; fi
}

command -v curl >/dev/null 2>&1 || die "curl is required to download trivy"

mkdir -p "$CACHE_ROOT"
WORK="$(mktemp -d "$CACHE_ROOT/.trivy-install.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# --- download (bounded retries) -------------------------------------------------
log "downloading $ASSET (v$TRIVY_VERSION)"
curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 600 \
    -o "$WORK/$ASSET" "$BASE/$ASSET" || die "download failed: $BASE/$ASSET"

# --- verify -----------------------------------------------------------------------
ACTUAL_SHA="$(sha256_of "$WORK/$ASSET")"
[[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] \
    || die "checksum mismatch for $ASSET (expected $EXPECTED_SHA, got $ACTUAL_SHA)"

if [[ "${TRIVY_VERIFY_OFFICIAL:-1}" == "1" ]]; then
    CHK="trivy_${TRIVY_VERSION}_checksums.txt"
    if curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 60 \
            -o "$WORK/$CHK" "$BASE/$CHK" 2>/dev/null; then
        OFFICIAL="$(awk -v a="$ASSET" '$2==a {print $1}' "$WORK/$CHK")"
        [[ -n "$OFFICIAL" ]] || die "$ASSET not listed in official $CHK"
        [[ "$OFFICIAL" == "$ACTUAL_SHA" ]] \
            || die "archive does not match the official $CHK (official $OFFICIAL, got $ACTUAL_SHA)"
        log "checksum verified against pinned value and official checksums file"
    else
        log "WARNING: official checksums file not reachable; pinned checksum verified only"
    fi
else
    log "checksum verified against pinned value"
fi

# --- extract and publish atomically -----------------------------------------------
tar -xzf "$WORK/$ASSET" -C "$WORK" trivy || die "could not extract trivy from $ASSET"
chmod +x "$WORK/trivy"
[[ "$(reported_version "$WORK/trivy" || true)" == "$TRIVY_VERSION" ]] \
    || die "installed binary does not report version $TRIVY_VERSION"

mkdir -p "$INSTALL_DIR"
mv -f "$WORK/trivy" "$BIN"
log "installed $BIN"
echo "$BIN"
