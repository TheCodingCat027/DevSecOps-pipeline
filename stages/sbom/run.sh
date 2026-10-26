#!/usr/bin/env bash
# stages/sbom/run.sh — STUB for the SBOM generation stage
#
# Owner: P3  |  Real tool: Syft v1.5.0
# Interface: contracts/stage-interface.md
# Also writes artifacts/sbom/sbom.cdx.json (CycloneDX format)

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "[sbom] ERROR: expected 2 arguments: <target_path> <output_dir>" >&2
    exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

[[ -e "$TARGET_PATH" ]] || { echo "[sbom] ERROR: target does not exist: $TARGET_PATH" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/artifacts/sbom"

echo "[stub] sbom: replace this stub with the real scanner (owner: P3)" >&2

# Copy the SARIF stub (zero results — SBOM is inventory, not findings)
cp "$REPO_ROOT/contracts/samples/sbom.sarif" "$OUTPUT_DIR/sbom.sarif"

# Write a minimal valid CycloneDX SBOM placeholder
cat > "$OUTPUT_DIR/artifacts/sbom/sbom.cdx.json" <<'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2026-01-01T00:00:00Z",
    "tools": [{"vendor": "anchore", "name": "syft", "version": "stub"}],
    "component": {"type": "application", "name": "demo-app-vulnerable", "version": "0.0.0-stub"}
  },
  "components": []
}
EOF

echo "[sbom] Done. SARIF: $OUTPUT_DIR/sbom.sarif, SBOM: $OUTPUT_DIR/artifacts/sbom/sbom.cdx.json" >&2
exit 0
