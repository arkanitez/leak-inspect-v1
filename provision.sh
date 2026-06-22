#!/usr/bin/env bash
# ===========================================================================
# provision.sh  —  build an OFFLINE bundle on a CONNECTED machine.
#
# Produces ./dist/leak-inspect-bundle/ containing:
#   wheels/      CPU-only Python wheels for the full runtime
#   models/      Prompt Guard 2 + inspector model snapshots
#   app/         the application
#   bundle.env   resolved config for the target
#   SHA256SUMS   integrity manifest
#
# Carry the bundle (or its tarball) into the enclave and run deploy.sh there.
# Nothing in deploy.sh touches the network.
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

# This script builds the air-gap dist ONLY — it never installs a service. The
# flags below are accepted for clarity and symmetry with setup.sh.
for _arg in "$@"; do
  case "$_arg" in
    dist|--dist|-dist|--dist-only) : ;;   # the default (and only) behavior
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "provision.sh: unknown argument '$_arg' — this script only builds the dist (see --help)." >&2; exit 2 ;;
  esac
done

# ---- configurable -------------------------------------------------------
TORCH_VER="${TORCH_VER:-}"          # empty = latest available CPU build; or set x.y.z
CPU_INDEX="https://download.pytorch.org/whl/cpu"
GUARD_MODEL="${GUARD_MODEL:-meta-llama/Llama-Prompt-Guard-2-86M}"
INSPECTOR_MODEL="${INSPECTOR_MODEL:-Qwen/Qwen3-4B-Instruct-2507}"
PREFIX="${PREFIX:-/opt/leak-inspect}"          # install location on the target
OUT="${OUT:-dist/leak-inspect-bundle}"
# HF_TOKEN may be required for gated repos (Llama / Qwen). Export it first.
# -------------------------------------------------------------------------

WHEELS="$OUT/wheels"; MODELS="$OUT/models"; APP="$OUT/app"
rm -rf "$OUT"; mkdir -p "$WHEELS" "$MODELS" "$APP"

echo "==> provisioning venv"
PROV=".venv-provision"
python3 -m venv "$PROV"; source "$PROV/bin/activate"
pip install --quiet --upgrade pip huggingface_hub

# Pass 1: CPU torch. Unpinned by default (the CPU index prunes old releases, so
# a hard pin rots); set TORCH_VER=x.y.z to force a specific build.
if [[ -n "$TORCH_VER" ]]; then TORCH_SPEC="torch==$TORCH_VER"; else TORCH_SPEC="torch"; fi
echo "==> downloading CPU torch ($TORCH_SPEC) from $CPU_INDEX"
pip download --dest "$WHEELS" --index-url "$CPU_INDEX" "$TORCH_SPEC"

# Pin torch to exactly the CPU build we just fetched, so pass 2 (which sees
# PyPI) cannot resolve accelerate's torch dependency to a newer CUDA wheel.
TORCH_WHL="$(ls "$WHEELS"/torch-*.whl | head -1)"
TORCH_GOT="$(basename "$TORCH_WHL" | sed -E 's/^torch-([^-]+)-.*/\1/')"
echo "torch==$TORCH_GOT" > "$OUT/.torch-constraint.txt"
echo "    got torch $TORCH_GOT"

echo "==> downloading the remaining wheels from PyPI"
grep -v -E '^\s*#|^\s*torch\b' requirements.txt > "$OUT/.req-notorch.txt"
pip download --dest "$WHEELS" --only-binary=:all: \
  --find-links "$WHEELS" -c "$OUT/.torch-constraint.txt" -r "$OUT/.req-notorch.txt"
rm -f "$OUT/.req-notorch.txt" "$OUT/.torch-constraint.txt"

echo "==> downloading models"
python - "$MODELS" "$GUARD_MODEL" "$INSPECTOR_MODEL" <<'PY'
import os, sys
from huggingface_hub import snapshot_download
dest, *repos = sys.argv[1:]
token = os.environ.get("HF_TOKEN")
for repo in repos:
    local = os.path.join(dest, repo.replace("/", "__"))
    print("    -", repo, "->", local)
    snapshot_download(repo_id=repo, local_dir=local, token=token,
                      ignore_patterns=["*.pth", "*.onnx", "original/*", "*.gguf"])
PY

echo "==> staging app"
if command -v rsync >/dev/null 2>&1; then
  rsync -a --exclude='__pycache__' --exclude='*.pyc' app/ "$APP/"
else
  cp -r app/. "$APP/"
  find "$APP" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
fi
cp requirements.txt "$OUT/"
cp deploy.sh "$OUT/" && chmod +x "$OUT/deploy.sh"
cp api_probe.py "$OUT/"

echo "==> writing bundle.env"
GUARD_DIR="models/$(echo "$GUARD_MODEL" | sed 's#/#__#g')"
INSP_DIR="models/$(echo "$INSPECTOR_MODEL" | sed 's#/#__#g')"
cat > "$OUT/bundle.env" <<EOF
# Resolved at provision time. deploy.sh rewrites the *_PATH values to absolute
# paths under \$PREFIX on the target.
PREFIX=$PREFIX
MODEL_BACKEND=transformers
HF_HUB_OFFLINE=1
TRANSFORMERS_OFFLINE=1
GUARD_MODEL_PATH=$GUARD_DIR
REVIEW_MODEL_PATH=$INSP_DIR
REVIEW_DTYPE=float32
REVIEW_MAXTOK=256
GUARD_THRESHOLD=0.5
DATA_DIR=$PREFIX/data
EOF

echo "==> computing SHA256SUMS"
( cd "$OUT" && find wheels models app bundle.env requirements.txt deploy.sh api_probe.py -type f -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS )

deactivate
echo "==> bundle ready: $OUT"
du -sh "$OUT" 2>/dev/null || true
echo "    (optional) tar:  tar -czf leak-inspect-bundle.tgz -C $(dirname "$OUT") $(basename "$OUT")"
