"""Runtime ApiInspector tests across all auth mechanisms, OAuth2 token caching /
fallback / refresh, fail-closed paths, and full worker integration. No weights."""
import os, json, time, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_VERDICT = {"schema_version": "3.0", "decision": "BLOCK", "risk_tier": "HIGH",
            "categories": [{"code": "CLASS_MARKING", "severity": "HIGH", "occurrences": "1"}],
            "injection_attempt_detected": False, "policy_conformant": False, "assessable": True}


class S:
    token_calls = 0
    chat_calls = 0
    token_mode = "ok"          # ok | reject_post
    chat_mode = "verdict"      # verdict | reject_first_token | 500
    last_chat_headers = {}

    @classmethod
    def reset(cls, token_mode="ok", chat_mode="verdict"):
        cls.token_calls = 0
        cls.chat_calls = 0
        cls.token_mode = token_mode
        cls.chat_mode = chat_mode
        cls.last_chat_headers = {}


def _server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(n)
            if self.path.endswith("/token"):
                S.token_calls += 1
                has_basic = self.headers.get("Authorization", "").startswith("Basic ")
                if S.token_mode == "reject_post" and not has_basic:
                    return self._json(401, {"error": "invalid_client"})
                return self._json(200, {"access_token": "tok-%d" % S.token_calls, "expires_in": 300})
            S.chat_calls += 1
            S.last_chat_headers = {k: v for k, v in self.headers.items()}
            auth = self.headers.get("Authorization", "")
            if S.chat_mode == "reject_first_token" and auth == "Bearer tok-1":
                return self._json(401, {"error": "expired"})
            if S.chat_mode == "500":
                return self._json(500, {"error": "boom"})
            return self._json(200, {"choices": [{"message": {"content": "x " + json.dumps(_VERDICT)}}]})
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def run():
    srv, port = _server()
    base = "http://127.0.0.1:%d" % port
    os.environ.update(GUARD_BACKEND="mock", INSPECTOR_BACKEND="api",
                      INSPECTOR_API_URL=base + "/v1/chat/completions",
                      INSPECTOR_API_MODEL="m", DATA_DIR=tempfile.mkdtemp(prefix="wl-api-"))
    from app.pipeline.backends import ApiInspector, parse_verdict
    import app.config as C
    import base64

    def cfg(**kw):
        for k, v in kw.items():
            setattr(C.cfg, k, v)

    assert parse_verdict('{"decision":"PASS","categories":[],"risk_tier":"NONE"}')["decision"] == "PASS"
    assert parse_verdict("nope")["decision"] == "BLOCK"
    print("parse_verdict OK")

    S.reset(); cfg(INSPECTOR_API_AUTH="bearer", INSPECTOR_API_KEY="abc123")
    assert ApiInspector().inspect("SECRET//NOFORN")["decision"] == "BLOCK"
    assert S.last_chat_headers.get("Authorization") == "Bearer abc123"
    print("bearer OK")

    S.reset(); cfg(INSPECTOR_API_AUTH="basic", INSPECTOR_API_CLIENT_ID="id", INSPECTOR_API_CLIENT_SECRET="sec")
    ApiInspector().inspect("x")
    assert S.last_chat_headers.get("Authorization") == "Basic " + base64.b64encode(b"id:sec").decode()
    print("basic OK")

    S.reset(); cfg(INSPECTOR_API_AUTH="header", INSPECTOR_API_ID_HEADER="X-Client-Id",
                   INSPECTOR_API_SECRET_HEADER="X-Client-Secret",
                   INSPECTOR_API_CLIENT_ID="cid", INSPECTOR_API_CLIENT_SECRET="csec")
    ApiInspector().inspect("x")
    assert S.last_chat_headers.get("X-Client-Id") == "cid"
    assert S.last_chat_headers.get("X-Client-Secret") == "csec"
    print("custom-header OK")

    S.reset(); cfg(INSPECTOR_API_AUTH="oauth2", INSPECTOR_API_TOKEN_URL=base + "/token",
                   INSPECTOR_API_CLIENT_ID="id", INSPECTOR_API_CLIENT_SECRET="sec", INSPECTOR_API_SCOPE="")
    insp = ApiInspector()
    assert insp.inspect("x")["decision"] == "BLOCK"
    assert S.last_chat_headers.get("Authorization") == "Bearer tok-1"
    insp.inspect("y")
    assert S.token_calls == 1 and S.chat_calls == 2, (S.token_calls, S.chat_calls)
    print("oauth2 happy + token caching OK (1 token fetch, 2 chats)")

    S.reset(token_mode="reject_post")
    insp = ApiInspector()
    assert insp.inspect("x")["decision"] == "BLOCK"
    assert S.token_calls == 2
    print("oauth2 post->basic fallback OK")

    S.reset(chat_mode="reject_first_token")
    insp = ApiInspector()
    assert insp.inspect("x")["decision"] == "BLOCK"
    assert S.token_calls == 2 and S.chat_calls == 2
    print("oauth2 refresh-on-401 OK")

    S.reset(chat_mode="500"); cfg(INSPECTOR_API_AUTH="none")
    fc = ApiInspector().inspect("x")
    assert fc["decision"] == "BLOCK" and fc["assessable"] is False and "_api_error" in fc
    print("fail-closed on HTTP 500 OK")

    cfg(INSPECTOR_API_URL="http://127.0.0.1:1/v1/chat/completions")
    fc = ApiInspector().inspect("x")
    assert fc["decision"] == "BLOCK" and fc["assessable"] is False
    print("fail-closed on unreachable OK")
    cfg(INSPECTOR_API_URL=base + "/v1/chat/completions")

    cfg(INSPECTOR_API_URL="")
    try:
        ApiInspector(); raise AssertionError("should raise")
    except RuntimeError:
        print("config guard OK")
    cfg(INSPECTOR_API_URL=base + "/v1/chat/completions", INSPECTOR_API_AUTH="none")

    S.reset()
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        assert c.get("/api/health").json()["inspector_backend"] == "api"
        jid = c.post("/api/jobs", data={"texts": ["routine note"]}).json()["id"]
        c.post("/api/jobs/%s/confirm" % jid)
        for _ in range(50):
            s = c.get("/api/jobs/%s/status" % jid).json()
            if s["status"] in ("DONE", "ERROR"):
                break
            time.sleep(0.2)
        assert s["status"] == "DONE" and s["items"][0]["decision"] == "BLOCK", s
    print("worker integration OK")

    srv.shutdown()
    print("\nALL API-INSPECTOR ASSERTIONS PASSED")


if __name__ == "__main__":
    run()
