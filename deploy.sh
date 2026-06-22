#!/usr/bin/env bash
# ===========================================================================
# deploy.sh  —  install the OFFLINE bundle on the TARGET (air-gapped) host.
# Run from inside an extracted bundle directory:  sudo ./deploy.sh
# Requires only Python 3 + venv on the target. Never touches the network.
# ===========================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

[[ -f bundle.env ]] || { echo "bundle.env not found — run inside the bundle dir"; exit 1; }
# shellcheck disable=SC1091
source bundle.env
PREFIX="${PREFIX:?bundle.env must set PREFIX}"
SERVICE="${SERVICE:-leak-inspect}"
HOST="${HOST:-0.0.0.0}"; PORT="${PORT:-8080}"
RUN_USER="${RUN_USER:-leakinspect}"

echo "==> verifying integrity (SHA256SUMS)"
sha256sum -c SHA256SUMS --quiet
echo "    OK"

# ---------------------------------------------------------------------------
# Inspector backend: the local bundled model (default) or a remote inference API.
# Prompts the operator interactively; honours a pre-set INSPECTOR_API_URL for
# non-interactive (automated) runs. The chosen API is tested for connectivity and
# compatibility before it is committed; on failure the operator can fall back to
# the local model or enter another API.
# ---------------------------------------------------------------------------
INSPECTOR_MODE="local"
API_URL="${INSPECTOR_API_URL:-}";          API_MODEL="${INSPECTOR_API_MODEL:-}"
API_AUTH="${INSPECTOR_API_AUTH:-none}";    API_KEY="${INSPECTOR_API_KEY:-}"
API_CID="${INSPECTOR_API_CLIENT_ID:-}";    API_CSEC="${INSPECTOR_API_CLIENT_SECRET:-}"
API_TOKEN_URL="${INSPECTOR_API_TOKEN_URL:-}"; API_SCOPE="${INSPECTOR_API_SCOPE:-}"
API_IDH="${INSPECTOR_API_ID_HEADER:-X-Client-Id}"
API_SECH="${INSPECTOR_API_SECRET_HEADER:-X-Client-Secret}"

api_probe() {   # runs the bundled probe against the current API_* vars
  T_URL="$API_URL" T_MODEL="$API_MODEL" T_AUTH="$API_AUTH" T_TIMEOUT=30 \
  T_KEY="$API_KEY" T_CID="$API_CID" T_CSEC="$API_CSEC" T_TOKEN_URL="$API_TOKEN_URL" \
  T_SCOPE="$API_SCOPE" T_IDH="$API_IDH" T_SECH="$API_SECH" \
  python3 api_probe.py
}

prompt_api() {  # interactively fill the API_* vars
  read -rp  "  Inference API URL (OpenAI-compatible …/v1/chat/completions): " API_URL
  read -rp  "  Model name the server serves: " API_MODEL
  echo      "  Authentication for this API:"
  echo      "    1) OAuth2 client-credentials (token endpoint -> bearer)"
  echo      "    2) HTTP Basic (client_id:client_secret)"
  echo      "    3) Custom headers (e.g. X-Client-Id / X-Client-Secret)"
  echo      "    4) Static bearer token"
  echo      "    5) None"
  local c h; read -rp "  Choose [1-5]: " c
  case "$c" in
    1) API_AUTH=oauth2
       read -rp  "    OAuth2 token endpoint URL: " API_TOKEN_URL
       read -rp  "    Client ID: " API_CID
       read -rsp "    Client secret: " API_CSEC; echo
       read -rp  "    Scope (optional, blank for none): " API_SCOPE ;;
    2) API_AUTH=basic
       read -rp  "    Client ID: " API_CID
       read -rsp "    Client secret: " API_CSEC; echo ;;
    3) API_AUTH=header
       read -rp  "    Client ID: " API_CID
       read -rsp "    Client secret: " API_CSEC; echo
       read -rp  "    ID header name [X-Client-Id]: " h;     API_IDH="${h:-X-Client-Id}"
       read -rp  "    Secret header name [X-Client-Secret]: " h; API_SECH="${h:-X-Client-Secret}" ;;
    4) API_AUTH=bearer
       read -rsp "    Bearer token: " API_KEY; echo ;;
    *) API_AUTH=none ;;
  esac
}

if [[ ! -f api_probe.py ]]; then
  echo "==> (api_probe.py not in this bundle — inspector will use the local model)"
elif [[ -n "$API_URL" ]]; then
  echo "==> testing pre-configured inference API: $API_URL"
  if out="$(api_probe 2>&1)"; then
    echo "    ✓ $out"; INSPECTOR_MODE="api"
  else
    echo "    ✗ inference API is not usable:"; echo "$out" | sed 's/^/      /'
    echo "    Falling back to the local model. Fix the API settings to use the API."
  fi
elif [[ -t 0 ]]; then
  read -rp "==> Use a remote inference API for the LLM inspector instead of the local model? [y/N]: " ans
  if [[ "${ans,,}" == y* ]]; then
    while :; do
      prompt_api
      echo "==> testing the inference API for connectivity and compatibility…"
      if out="$(api_probe 2>&1)"; then
        echo "    ✓ $out"
        echo "    Using this inference API for the inspector."
        INSPECTOR_MODE="api"; break
      fi
      echo "    ✗ This inference API is not usable:"
      echo "$out" | sed 's/^/      /'
      read -rp "    Proceed with the LOCAL model, or RETRY another API? [local/retry]: " d
      [[ "${d,,}" == r* ]] || { INSPECTOR_MODE="local"; break; }
    done
  fi
else
  echo "==> non-interactive and no INSPECTOR_API_URL set — using the local bundled model."
fi
echo "==> inspector backend: $INSPECTOR_MODE"

echo "==> creating $PREFIX"
install -d -m 0750 "$PREFIX" "$PREFIX/data" "$PREFIX/data/hf" "$PREFIX/data/cache"
cp -r app "$PREFIX/app"
cp -r models "$PREFIX/models"
cp requirements.txt bundle.env "$PREFIX/"

echo "==> offline venv + wheels"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --no-index --find-links wheels --upgrade pip || true
"$PREFIX/venv/bin/pip" install --no-index --find-links wheels -r requirements.txt

echo "==> resolving absolute model paths"
GUARD_ABS="$PREFIX/${GUARD_MODEL_PATH}"
INSP_ABS="$PREFIX/${REVIEW_MODEL_PATH}"
ENV_FILE="$PREFIX/leak-inspect.env"
{
  grep -v -E '^(GUARD_MODEL_PATH|REVIEW_MODEL_PATH|PREFIX|DATA_DIR)=' bundle.env
  echo "GUARD_MODEL_PATH=$GUARD_ABS"
  echo "REVIEW_MODEL_PATH=$INSP_ABS"
  echo "DATA_DIR=$PREFIX/data"
  echo "HF_HOME=$PREFIX/data/hf"
  echo "XDG_CACHE_HOME=$PREFIX/data/cache"
  if [[ "$INSPECTOR_MODE" == "api" ]]; then
    echo "INSPECTOR_BACKEND=api"
    echo "INSPECTOR_API_URL=$API_URL"
    echo "INSPECTOR_API_MODEL=$API_MODEL"
    echo "INSPECTOR_API_AUTH=$API_AUTH"
    [[ -n "$API_KEY" ]]       && echo "INSPECTOR_API_KEY=$API_KEY"
    [[ -n "$API_CID" ]]       && echo "INSPECTOR_API_CLIENT_ID=$API_CID"
    [[ -n "$API_CSEC" ]]      && echo "INSPECTOR_API_CLIENT_SECRET=$API_CSEC"
    [[ -n "$API_TOKEN_URL" ]] && echo "INSPECTOR_API_TOKEN_URL=$API_TOKEN_URL"
    [[ -n "$API_SCOPE" ]]     && echo "INSPECTOR_API_SCOPE=$API_SCOPE"
    if [[ "$API_AUTH" == "header" ]]; then
      echo "INSPECTOR_API_ID_HEADER=$API_IDH"
      echo "INSPECTOR_API_SECRET_HEADER=$API_SECH"
    fi
  fi
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"   # may contain a client secret / token

# service account
id "$RUN_USER" &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$RUN_USER" || true
chown -R "$RUN_USER":"$RUN_USER" "$PREFIX"

echo "==> installing systemd unit"
cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=Cross-Domain Leak-Inspect pipeline
After=network.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$PREFIX
Environment=PYTHONPATH=$PREFIX
EnvironmentFile=$ENV_FILE
ExecStart=$PREFIX/venv/bin/uvicorn app.main:app --host $HOST --port $PORT
Restart=on-failure
RestartSec=3
# hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=$PREFIX/data
# NOTE: egress is controlled at the network/host-firewall layer (the air-gap
# boundary). Do not add systemd IPAddress* filters here — they also block the
# inbound client connections the console needs.

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE}.service"

echo "==> validating ${SERVICE} is serving"
if python3 - "http://127.0.0.1:${PORT}/api/health" <<'PY'
import sys, time, urllib.request
url = sys.argv[1]
for _ in range(30):
    try:
        urllib.request.urlopen(url, timeout=2).read()
        print("    UP —", url); sys.exit(0)
    except Exception:
        time.sleep(1)
sys.exit(1)
PY
then
    echo "    ${SERVICE} is healthy."
else
    echo "    ERROR: ${SERVICE} did not become healthy on 127.0.0.1:${PORT}" >&2
    echo "    inspect:  journalctl -u ${SERVICE} -e" >&2
    systemctl --no-pager --full status "${SERVICE}.service" || true
    exit 1
fi
echo "    console: http://<host>:$PORT/   ·   API docs: /docs"
