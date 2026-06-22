#!/usr/bin/env bash
# ===========================================================================
# enable-https.sh — put nginx + a Let's Encrypt IP-address certificate in front
# of leak-inspect, so the demo is reachable over HTTPS at the EC2 public IP:
#
#     browser --HTTPS--> nginx (:443) --proxy--> 127.0.0.1:8080 (leak-inspect)
#
# PREREQUISITES (must be true before running):
#   * leak-inspect is installed and running (./setup.sh).
#   * Security group: port 80 open to 0.0.0.0/0 (ACME HTTP-01 challenge + every
#     ~6-day renewal) and port 443 open to your access source.
#   * A STATIC public IP — allocate and associate an Elastic IP. Let's Encrypt
#     IP certificates are short-lived (~6 days) and are bound to the IP; if the
#     IP changes the certificate, nginx config and renewal all break.
#
# Let's Encrypt IP certs auto-renew via certbot's timer; a deploy-hook reloads
# nginx. The app is bound to 127.0.0.1 so only nginx is publicly reachable.
#
# Usage:  sudo ./enable-https.sh            (production, trusted cert)
#         sudo STAGING=1 ./enable-https.sh  (LE staging, untrusted — for testing)
#         sudo PUBLIC_IP=1.2.3.4 ./enable-https.sh   (skip IMDS discovery)
#         sudo EMAIL=you@example.com ./enable-https.sh
# ===========================================================================
set -euo pipefail

SERVICE="${SERVICE:-leak-inspect}"
APP_PORT="${APP_PORT:-8080}"
WEBROOT="${WEBROOT:-/var/www/certbot}"
STAGING="${STAGING:-0}"
EMAIL="${EMAIL:-}"
PUBLIC_IP="${PUBLIC_IP:-}"
SITE="/etc/nginx/sites-available/leak-inspect"

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo ./enable-https.sh"; exit 1; }

health_ok() {
  python3 - "$1" <<'PY'
import sys, urllib.request
try:
    urllib.request.urlopen(sys.argv[1], timeout=3).read(); sys.exit(0)
except Exception:
    sys.exit(1)
PY
}

# --- 1. validate leak-inspect is actually running ------------------------
echo "==> [1/7] checking ${SERVICE} is running"
if ! systemctl is-active --quiet "$SERVICE"; then
  echo "ERROR: ${SERVICE} is not active. Deploy it first: ./setup.sh" >&2; exit 1
fi
if ! health_ok "http://127.0.0.1:${APP_PORT}/api/health"; then
  echo "ERROR: ${SERVICE} health check failed on 127.0.0.1:${APP_PORT}." >&2
  echo "       inspect: journalctl -u ${SERVICE} -e" >&2; exit 1
fi
echo "    OK — ${SERVICE} healthy on 127.0.0.1:${APP_PORT}"

# --- 2. install nginx + a current certbot --------------------------------
echo "==> [2/7] installing nginx + certbot"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx curl
# certbot via snap — the apt build is too old for --ip-address / IP certificates.
if command -v snap >/dev/null 2>&1; then
  snap install --classic certbot >/dev/null 2>&1 || true
  ln -sf /snap/bin/certbot /usr/bin/certbot 2>/dev/null || true
fi
command -v certbot >/dev/null 2>&1 || apt-get install -y -qq certbot
if ! certbot --help all 2>/dev/null | grep -q -- '--ip-address'; then
  echo "ERROR: this certbot is too old for IP certificates (no --ip-address)." >&2
  echo "       Install the snap: sudo snap install --classic certbot" >&2; exit 1
fi

# --- 3. discover the public IP (IMDSv2) -----------------------------------
echo "==> [3/7] determining public IP"
if [[ -z "$PUBLIC_IP" ]]; then
  TOKEN="$(curl -sS -X PUT 'http://169.254.169.254/latest/api/token' \
           -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' --max-time 3 || true)"
  if [[ -n "$TOKEN" ]]; then
    PUBLIC_IP="$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" --max-time 3 \
                 http://169.254.169.254/latest/meta-data/public-ipv4 || true)"
  fi
fi
if [[ -z "$PUBLIC_IP" ]]; then
  echo "ERROR: could not determine the public IP via IMDS. Pass it explicitly:" >&2
  echo "       sudo PUBLIC_IP=<your.elastic.ip> ./enable-https.sh" >&2; exit 1
fi
echo "    public IP: ${PUBLIC_IP}"
echo "    (reminder: this should be an ELASTIC IP, or the ~6-day cert breaks on restart)"

# --- 4. phase-1 nginx: HTTP only, to serve the ACME challenge -------------
echo "==> [4/7] configuring nginx for the ACME challenge"
mkdir -p "$WEBROOT"
cat > "$SITE" <<NGINX
server {
    listen 80 default_server;
    server_name ${PUBLIC_IP};
    location /.well-known/acme-challenge/ { root ${WEBROOT}; }
    location / { default_type text/plain; return 200 "leak-inspect: provisioning TLS\n"; }
}
NGINX
ln -sf "$SITE" /etc/nginx/sites-enabled/leak-inspect
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

# --- 5. obtain the Let's Encrypt IP certificate (webroot; obtain-only) ----
echo "==> [5/7] requesting Let's Encrypt IP certificate (short-lived, ~6 days)"
staging_flag=(); [[ "$STAGING" == "1" ]] && staging_flag=(--staging)
email_flag=(--register-unsafely-without-email); [[ -n "$EMAIL" ]] && email_flag=(-m "$EMAIL")
certbot certonly "${staging_flag[@]}" \
  --non-interactive --agree-tos "${email_flag[@]}" \
  --preferred-profile shortlived \
  --webroot --webroot-path "$WEBROOT" \
  --ip-address "$PUBLIC_IP" \
  --deploy-hook "systemctl reload nginx"
CERT_DIR="/etc/letsencrypt/live/${PUBLIC_IP}"
[[ -f "$CERT_DIR/fullchain.pem" ]] || { echo "ERROR: certificate was not issued at $CERT_DIR" >&2; exit 1; }
echo "    issued: ${CERT_DIR}/fullchain.pem"

# --- 6. phase-2 nginx: full HTTPS reverse proxy --------------------------
echo "==> [6/7] enabling HTTPS reverse proxy + binding app to localhost"
cat > "$SITE" <<NGINX
server {
    listen 80 default_server;
    server_name ${PUBLIC_IP};
    location /.well-known/acme-challenge/ { root ${WEBROOT}; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl default_server;
    server_name ${PUBLIC_IP};

    ssl_certificate     ${CERT_DIR}/fullchain.pem;
    ssl_certificate_key ${CERT_DIR}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 120m;     # allow document uploads (app caps apply behind this)
    proxy_read_timeout   600s;     # inspection can take minutes across many segments
    proxy_send_timeout   600s;

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINX
nginx -t
systemctl reload nginx

# Bind the app to loopback so nginx is the only public listener. (This restarts
# the service, which reloads the model — a one-time few-minute warm-up.)
UNIT="/etc/systemd/system/${SERVICE}.service"
if grep -q -- '--host 0.0.0.0' "$UNIT"; then
  sed -i 's/--host 0.0.0.0/--host 127.0.0.1/' "$UNIT"
  systemctl daemon-reload
  systemctl restart "$SERVICE"
fi

# --- 7. validate the full TLS chain locally ------------------------------
echo "==> [7/7] validating HTTPS locally (TLS -> nginx -> app)"
curl_k=(); [[ "$STAGING" == "1" ]] && curl_k=(-k)   # staging cert is untrusted
# wait for the app to come back after the restart, then test through nginx+TLS
for _ in $(seq 1 30); do health_ok "http://127.0.0.1:${APP_PORT}/api/health" && break || sleep 1; done
if curl -fsS "${curl_k[@]}" --resolve "${PUBLIC_IP}:443:127.0.0.1" \
     "https://${PUBLIC_IP}/api/health" >/dev/null 2>&1; then
  echo "    HTTPS OK (TLS terminated by nginx, proxied to the app)"
else
  echo "    WARNING: local HTTPS check failed — check 'nginx -t', the cert, and the service" >&2
fi

cat <<EOF
──────────────────────────────────────────────────────────────────────
  HTTPS is live:   https://${PUBLIC_IP}/         (API docs: /docs)
  Certificate  :   Let's Encrypt IP cert, ~6 days, auto-renews (certbot.timer)
  App binding  :   127.0.0.1:${APP_PORT}  (only nginx is public)
  nginx config :   ${SITE}    ·    sudo systemctl status nginx
  Reminder     :   keep port 80 open to 0.0.0.0/0 for renewals; restrict 443
                   to your IP (the demo has no authentication).
$( [[ "$STAGING" == "1" ]] && echo "  NOTE: STAGING cert is UNTRUSTED — browsers will warn. Re-run without STAGING=1 for a real cert." )
──────────────────────────────────────────────────────────────────────
EOF
