"""Drives the REAL deploy.sh inspector-backend selection + env-file emission
(extracted verbatim from deploy.sh) on the non-interactive path, against a stub
inference API. Validates the bash var plumbing and the env keys written, without
needing systemd/sudo. Cases: none-auth success, oauth2 success, dead-URL->local."""
import os, re, json, tempfile, textwrap, subprocess, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VERDICT = {"decision": "PASS", "categories": [], "risk_tier": "NONE",
           "injection_attempt_detected": False, "policy_conformant": True, "assessable": True}


def _server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _j(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path.endswith("/token"):
                return self._j(200, {"access_token": "tok-1", "expires_in": 300})
            return self._j(200, {"choices": [{"message": {"content": json.dumps(VERDICT)}}]})
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _block(src, start, end):
    lines = src.splitlines()
    i = next(k for k, ln in enumerate(lines) if ln.startswith(start))
    j = next(k for k, ln in enumerate(lines) if ln.startswith(end) and k >= i)
    return "\n".join(lines[i:j + 1])


def run():
    here = os.path.dirname(os.path.abspath(__file__))
    deploy = open(os.path.join(here, "deploy.sh")).read()
    selection = _block(deploy, 'INSPECTOR_MODE="local"', 'echo "==> inspector backend')
    emission = _block(deploy, 'ENV_FILE="$PREFIX/leak-inspect.env"', 'chmod 600 "$ENV_FILE"')
    assert "api_probe.py" in selection and "INSPECTOR_BACKEND=api" in emission

    srv, port = _server()
    base = "http://127.0.0.1:%d" % port

    def harness(extra_env):
        tmp = tempfile.mkdtemp(prefix="wl-deploy-")
        # the probe is invoked as `python3 api_probe.py` from CWD
        subprocess.run(["cp", os.path.join(here, "api_probe.py"), tmp], check=True)
        script = textwrap.dedent('''\
            set -euo pipefail
            cd "%s"
            PREFIX="%s/opt"
            mkdir -p "$PREFIX/data/hf" "$PREFIX/data/cache"
            GUARD_ABS="$PREFIX/models/guard"
            INSP_ABS="$PREFIX/models/insp"
            cat > bundle.env <<'BE'
            MODEL_BACKEND=transformers
            GUARD_THRESHOLD=0.5
            APP_TITLE=Leak Inspect
            BE
            %s
            %s
            echo "RESULT_MODE=$INSPECTOR_MODE"
            echo "RESULT_ENV=$ENV_FILE"
        ''') % (tmp, tmp, selection, emission)
        e = dict(os.environ); e.update(extra_env)
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e)
        out = p.stdout + p.stderr
        assert p.returncode == 0, out
        mode = re.search(r"RESULT_MODE=(\w+)", out).group(1)
        envf = re.search(r"RESULT_ENV=(\S+)", out).group(1)
        envtxt = open(envf).read()
        perm = oct(os.stat(envf).st_mode & 0o777)
        return mode, envtxt, perm, out

    # 1) none-auth, reachable + compatible -> api
    mode, envtxt, perm, _ = harness({
        "INSPECTOR_API_URL": base + "/v1/chat/completions", "INSPECTOR_API_MODEL": "m"})
    assert mode == "api", mode
    assert "INSPECTOR_BACKEND=api" in envtxt
    assert ("INSPECTOR_API_URL=" + base + "/v1/chat/completions") in envtxt
    assert "INSPECTOR_API_MODEL=m" in envtxt and "INSPECTOR_API_AUTH=none" in envtxt
    assert "MODEL_BACKEND=transformers" in envtxt  # bundle.env passthrough preserved
    assert "GUARD_MODEL_PATH=" in envtxt and "REVIEW_MODEL_PATH=" in envtxt
    assert "INSPECTOR_API_CLIENT_SECRET" not in envtxt  # no creds leaked for none-auth
    assert perm == "0o600", perm
    print("  [PASS] none-auth non-interactive -> api; env keys + 0600 correct")

    # 2) oauth2 -> api, with the oauth2 keys emitted (and secret present, file locked)
    mode, envtxt, perm, _ = harness({
        "INSPECTOR_API_URL": base + "/v1/chat/completions", "INSPECTOR_API_MODEL": "m",
        "INSPECTOR_API_AUTH": "oauth2", "INSPECTOR_API_TOKEN_URL": base + "/token",
        "INSPECTOR_API_CLIENT_ID": "cid", "INSPECTOR_API_CLIENT_SECRET": "csecret",
        "INSPECTOR_API_SCOPE": "inspect.read"})
    assert mode == "api", mode
    for need in ("INSPECTOR_BACKEND=api", "INSPECTOR_API_AUTH=oauth2",
                 "INSPECTOR_API_TOKEN_URL=" + base + "/token",
                 "INSPECTOR_API_CLIENT_ID=cid", "INSPECTOR_API_CLIENT_SECRET=csecret",
                 "INSPECTOR_API_SCOPE=inspect.read"):
        assert need in envtxt, need
    assert perm == "0o600", perm
    print("  [PASS] oauth2 non-interactive -> api; all oauth2 keys emitted; 0600")

    # 3) dead URL -> falls back to local, no api config written
    mode, envtxt, perm, _ = harness({
        "INSPECTOR_API_URL": "http://127.0.0.1:1/v1/chat/completions", "INSPECTOR_API_MODEL": "m"})
    assert mode == "local", mode
    assert "INSPECTOR_BACKEND=api" not in envtxt
    assert "MODEL_BACKEND=transformers" in envtxt
    print("  [PASS] dead-URL non-interactive -> local fallback; no api config written")

    srv.shutdown()
    print("\nALL DEPLOY-SELECTION ASSERTIONS PASSED")


if __name__ == "__main__":
    run()
