#!/usr/bin/env bash
# ===========================================================================
# setup.sh — one command on a CONNECTED EC2 box.
#
# Builds the offline bundle and installs it as a managed systemd service — the
# SAME install path as the air-gapped enclave (deploy.sh), just on a box that
# still has network for the download phase:
#
#   1. provision.sh  -> download CPU wheels + models, build dist/leak-inspect-bundle/
#   2. deploy.sh      -> verify integrity, install offline under /opt, run via systemd
#
# The service (leak-inspect) survives SSH disconnects and reboots and restarts
# on failure. No terminal multiplexer involved. Once it is up you can cut egress
# and it keeps serving, fully offline.
#
# Modes (positional arg; if omitted, it prompts when run interactively):
#   ./setup.sh dist     build the air-gap bundle ONLY (provision) — installs nothing here
#   ./setup.sh deploy   build the bundle AND install the web service here (default)
# 'dist' needs no sudo; use it on a staging box to produce the transfer bundle.
#
# Quick, low-RAM look with NO models (foreground dev server, Ctrl-C to stop):
#   DEMO_BACKEND=mock ./setup.sh
#
# Notes:
#   * The Prompt Guard 2 repo is gated — export HF_TOKEN before running.
#   * The default inspector (Qwen3-4B, float32 on CPU) needs ~18-20 GB RAM to
#     run. On a smaller box override INSPECTOR_MODEL=<smaller-instruct> or use
#     DEMO_BACKEND=mock (the bundle still builds with the real models).
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

DEMO_BACKEND="${DEMO_BACKEND:-transformers}"
PORT="${PORT:-8080}"
BUNDLE="dist/leak-inspect-bundle"

# ---- mode: dist (build bundle only) | deploy (build + install here) ----------
MODE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    dist|--dist|-dist|--dist-only)  MODE="dist" ;;
    deploy|--deploy|--install|-i)   MODE="deploy" ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "setup.sh: unknown argument '$1' (use: dist | deploy | --help)" >&2; exit 2 ;;
  esac
  shift
done
MODE="${MODE:-${SETUP_MODE:-}}"

if [[ "$DEMO_BACKEND" == "mock" ]]; then
  echo "==> mock demo — foreground dev server (Ctrl-C to stop)"
  exec ./run-local.sh
fi

: "${HF_TOKEN:?HF_TOKEN is required for the gated model repos. For a model-free demo run: DEMO_BACKEND=mock ./setup.sh}"

# Resolve the mode: prompt when interactive, default to deploy otherwise.
if [[ -z "$MODE" ]]; then
  if [[ -t 0 ]]; then
    echo "What would you like to do?"
    echo "  1) Build the air-gap dist only   — download wheels + models, package the bundle"
    echo "  2) Build the dist AND install the web service here (systemd)"
    read -rp "Choose [1/2] (default 2): " _a
    case "${_a:-2}" in 1) MODE="dist" ;; *) MODE="deploy" ;; esac
  else
    MODE="deploy"   # backward-compatible default for non-interactive runs
  fi
fi

if [[ "$MODE" == "dist" ]]; then
  echo "==> building the air-gap dist only (downloading wheels + models)…"
  ./provision.sh
  cat <<EOF
──────────────────────────────────────────────────────────────────────
  Air-gap dist built:  ${BUNDLE}/
  Nothing was installed on this box.

  Package it for transfer:
      tar -czf leak-inspect-bundle.tgz -C dist leak-inspect-bundle

  Then, inside the enclave (fully offline):
      tar -xzf leak-inspect-bundle.tgz
      cd leak-inspect-bundle && sudo ./deploy.sh
  deploy.sh verifies SHA256SUMS, installs under /opt via systemd, and
  prompts to use a remote inference API or the bundled local model.
──────────────────────────────────────────────────────────────────────
EOF
  exit 0
fi

echo "==> [1/2] building the offline bundle (downloading wheels + models)…"
./provision.sh

echo "==> [2/2] installing as a systemd service (sudo)…"
( cd "$BUNDLE" && sudo --preserve-env=HOST,PORT ./deploy.sh )

if [[ "${ENABLE_HTTPS:-0}" == "1" ]]; then
  echo "==> enabling HTTPS (nginx + Let's Encrypt IP certificate)…"
  sudo --preserve-env=STAGING,EMAIL,PUBLIC_IP ./enable-https.sh
  exit 0
fi

cat <<EOF
──────────────────────────────────────────────────────────────────────
  Service      : leak-inspect  (systemd — survives disconnect & reboot)
  Status       : sudo systemctl status leak-inspect
  Live logs    : sudo journalctl -u leak-inspect -f
  Restart      : sudo systemctl restart leak-inspect
  Console      : http://<this-host-public-ip>:${PORT}/    ·    API docs: /docs
  Air-gap copy : ${BUNDLE}/   (tar -czf bundle.tgz -C dist leak-inspect-bundle)

  To expose publicly over HTTPS (nginx + Let's Encrypt IP certificate):
    1. Associate an ELASTIC IP (the ~6-day cert is bound to the IP).
    2. Security group: open 80 to 0.0.0.0/0 (ACME) and 443 to your IP.
    3. Run:  sudo ./enable-https.sh      (or re-run: ENABLE_HTTPS=1 ./setup.sh)
──────────────────────────────────────────────────────────────────────
EOF
