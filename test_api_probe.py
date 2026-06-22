"""Tests api_probe.py (the deploy-time connectivity + compatibility probe) as a
subprocess against stub servers, exactly as deploy.sh invokes it. Stdlib only."""
import os, sys, json, subprocess, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

CFG = {"chat": "verdict", "token": "ok", "auth_required": None}
VERDICT = {"decision": "PASS", "categories": [], "risk_tier": "NONE",
           "injection_attempt_detected": False, "policy_conformant": True, "assessable": True}


def _server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj, raw=False):
            body = obj.encode() if raw else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(n)
            if self.path.endswith("/token"):
                if CFG["token"] == "reject":
                    return self._send(401, {"error": "invalid_client"})
                return self._send(200, {"access_token": "tok-123", "expires_in": 300})
            if CFG["auth_required"] and not self.headers.get(CFG["auth_required"]):
                return self._send(401, {"error": "unauthorized"})
            m = CFG["chat"]
            if m == "verdict":
                return self._send(200, {"choices": [{"message": {"content": "Here:\n" + json.dumps(VERDICT)}}]})
            if m == "noverdict":
                return self._send(200, {"choices": [{"message": {"content": "I cannot comply."}}]})
            if m == "noshape":
                return self._send(200, {"result": "some other api"})
            if m == "notjson":
                return self._send(200, "plain text not json", raw=True)
            if m == "500":
                return self._send(500, {"error": "boom"})
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def run():
    srv, port = _server()
    base = "http://127.0.0.1:%d" % port
    chat, token = base + "/v1/chat/completions", base + "/token"
    here = os.path.dirname(os.path.abspath(__file__))

    def probe(env):
        e = dict(os.environ); e.update(T_URL=chat, T_MODEL="m", T_TIMEOUT="5", **env)
        p = subprocess.run([sys.executable, "api_probe.py"], cwd=here,
                           capture_output=True, text=True, env=e)
        return p.returncode, (p.stdout + p.stderr).strip()

    def expect(name, env, code, needle):
        rc, out = probe(env)
        ok = rc == code and needle.lower() in out.lower()
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
        assert ok, "%s: expected rc=%d & %r; got rc=%d: %s" % (name, code, needle, rc, out)

    CFG.update(chat="verdict", token="ok", auth_required=None)
    expect("none auth + verdict", {"T_AUTH": "none"}, 0, "OK: reachable")
    expect("bearer", {"T_AUTH": "bearer", "T_KEY": "abc"}, 0, "parseable verdict")
    expect("basic", {"T_AUTH": "basic", "T_CID": "id", "T_CSEC": "sec"}, 0, "decision=PASS")
    expect("header", {"T_AUTH": "header", "T_CID": "id", "T_CSEC": "sec"}, 0, "OK:")
    CFG.update(auth_required="Authorization")
    expect("oauth2 happy", {"T_AUTH": "oauth2", "T_CID": "id", "T_CSEC": "sec", "T_TOKEN_URL": token}, 0, "OK:")

    CFG.update(token="reject", auth_required="Authorization")
    expect("oauth2 token rejected", {"T_AUTH": "oauth2", "T_CID": "id", "T_CSEC": "sec", "T_TOKEN_URL": token},
           1, "token request was rejected")
    CFG.update(token="ok", auth_required="X-Need-Auth")
    expect("chat auth rejected", {"T_AUTH": "none"}, 1, "Authentication was rejected")
    CFG.update(auth_required=None, chat="noshape")
    expect("wrong shape", {"T_AUTH": "none"}, 1, "not the OpenAI chat-completions response shape")
    CFG.update(chat="notjson")
    expect("not json", {"T_AUTH": "none"}, 1, "not with JSON")
    CFG.update(chat="noverdict")
    expect("unparseable verdict", {"T_AUTH": "none"}, 1, "not with the required JSON verdict")
    CFG.update(chat="500")
    expect("http 500", {"T_AUTH": "none"}, 1, "HTTP 500")

    e = dict(os.environ)
    e.update(T_URL="http://127.0.0.1:1/v1/chat/completions", T_MODEL="m", T_AUTH="none", T_TIMEOUT="3")
    p = subprocess.run([sys.executable, "api_probe.py"], cwd=here, capture_output=True, text=True, env=e)
    assert p.returncode == 1 and "could not reach" in (p.stdout + p.stderr).lower()
    print("  [PASS] unreachable endpoint")

    srv.shutdown()
    print("\nALL PROBE ASSERTIONS PASSED")


if __name__ == "__main__":
    run()
