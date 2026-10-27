#!/usr/bin/env bash
# stages/secrets/install.sh — ensure the PINNED Gitleaks binary is available.
#
# Prints the absolute path of the gitleaks binary on STDOUT (and nothing else).
# All diagnostics go to STDERR.  Idempotent: a second call is a cheap no-op.
#
# Cache layout (document in README so CI can cache it):
#   ${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/gitleaks-<version>/gitleaks
#
# Environment knobs (all optional):
#   GITLEAKS_BIN              Use this binary instead of installing (tests / air-gapped use).
#                             It must exist and be executable; no version check is done.
#   GITLEAKS_DOWNLOAD_BASE    Base URL holding the release assets (default: official GitHub
#                             release for the pinned version).  Use for an internal mirror.
#   GITLEAKS_VERIFY_OFFICIAL  1 (default) = also cross-check the archive against the
#                             official <version>_checksums.txt published in the release.
#                             The pinned checksum below is ALWAYS enforced.
#   XDG_CACHE_HOME            Relocates the cache.
#
# Exit: 0 ok, 1 install failed.

set -euo pipefail

GITLEAKS_VERSION="8.30.1"

# SHA-256 of the release archives, copied from the project's official
# gitleaks_8.30.1_checksums.txt (https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1).
declare -A PINNED_SHA256=(
    [linux_x64]="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    [linux_arm64]="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
    [darwin_x64]="dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"
    [darwin_arm64]="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
)

log() { echo "[secrets:install] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# --- test / mirror override ---------------------------------------------------
if [[ -n "${GITLEAKS_BIN:-}" ]]; then
    [[ -x "$GITLEAKS_BIN" ]] || die "GITLEAKS_BIN is set but not executable: $GITLEAKS_BIN"
    echo "$GITLEAKS_BIN"
    exit 0
fi

CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops"
INSTALL_DIR="$CACHE_ROOT/gitleaks-$GITLEAKS_VERSION"
BIN="$INSTALL_DIR/gitleaks"

# --- already installed? -------------------------------------------------------
if [[ -x "$BIN" ]]; then
    if [[ "$("$BIN" version 2>/dev/null || true)" == "$GITLEAKS_VERSION" ]]; then
        echo "$BIN"
        exit 0
    fi
    log "cached binary has the wrong version; reinstalling"
fi

# --- platform detection -------------------------------------------------------
case "$(uname -s)" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *) die "unsupported OS: $(uname -s)" ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  ARCH="x64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
esac
PLATFORM="${OS}_${ARCH}"
EXPECTED_SHA="${PINNED_SHA256[$PLATFORM]:-}"
[[ -n "$EXPECTED_SHA" ]] || die "no pinned checksum for platform $PLATFORM"

ASSET="gitleaks_${GITLEAKS_VERSION}_${PLATFORM}.tar.gz"
BASE="${GITLEAKS_DOWNLOAD_BASE:-https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}}"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    else die "neither sha256sum nor shasum is available"; fi
}

command -v curl >/dev/null 2>&1 || die "curl is required to download gitleaks"

mkdir -p "$CACHE_ROOT"
WORK="$(mktemp -d "$CACHE_ROOT/.gitleaks-install.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# --- download (bounded retries) -------------------------------------------------
log "downloading $ASSET (v$GITLEAKS_VERSION)"
curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 300 \
    -o "$WORK/$ASSET" "$BASE/$ASSET" || die "download failed: $BASE/$ASSET"

# --- verify -----------------------------------------------------------------------
ACTUAL_SHA="$(sha256_of "$WORK/$ASSET")"
[[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] \
    || die "checksum mismatch for $ASSET (expected $EXPECTED_SHA, got $ACTUAL_SHA)"

if [[ "${GITLEAKS_VERIFY_OFFICIAL:-1}" == "1" ]]; then
    CHK="gitleaks_${GITLEAKS_VERSION}_checksums.txt"
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
tar -xzf "$WORK/$ASSET" -C "$WORK" gitleaks || die "could not extract gitleaks from $ASSET"
chmod +x "$WORK/gitleaks"
[[ "$("$WORK/gitleaks" version 2>/dev/null || true)" == "$GITLEAKS_VERSION" ]] \
    || die "installed binary does not report version $GITLEAKS_VERSION"

mkdir -p "$INSTALL_DIR"
mv -f "$WORK/gitleaks" "$BIN"
log "installed $BIN"
echo "$BIN"
