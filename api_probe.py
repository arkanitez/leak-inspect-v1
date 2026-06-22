#!/usr/bin/env python3
"""Connectivity + compatibility probe for a remote inference API.

deploy.sh runs this before wiring the inspector to a remote endpoint. It performs
the chosen auth, sends the *real* inspector system prompt with a benign sample,
and checks that the endpoint (a) is reachable, (b) speaks the OpenAI
chat-completions contract, and (c) returns a parseable verdict. On any failure it
prints a specific reason (and a short detail) and exits non-zero, so the script
can explain how/why it is incompatible. Standard library only.

All inputs arrive as T_* environment variables (set by deploy.sh):
  T_URL, T_MODEL, T_AUTH(none|bearer|basic|header|oauth2), T_TIMEOUT,
  T_KEY (bearer), T_CID/T_CSEC (basic|header|oauth2),
  T_TOKEN_URL/T_SCOPE (oauth2), T_IDH/T_SECH (header).
"""
import os
import sys
import json
import base64
import urllib.request
import urllib.parse
import urllib.error

TIMEOUT = float(os.environ.get("T_TIMEOUT", "30"))


def die(reason, detail=""):
    print("REASON: " + reason)
    if detail:
        print("DETAIL: " + detail.strip()[:300])
    sys.exit(1)


def _prompt():
    """The real inspector system prompt from the bundle, with a safe fallback."""
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(here, "app", "prompts", "inspector_system_prompt.txt"),
              os.path.join("app", "prompts", "inspector_system_prompt.txt")):
        try:
            with open(p, encoding="utf-8") as f:
                return f.read()
        except OSError:
            continue
    return ('Respond ONLY with a JSON object: {"decision":"PASS|REVIEW|BLOCK",'
            '"categories":[],"risk_tier":"NONE","injection_attempt_detected":false,'
            '"policy_conformant":true,"assessable":true}')


def _oauth_token():
    cid, csec = os.environ.get("T_CID", ""), os.environ.get("T_CSEC", "")
    token_url = os.environ.get("T_TOKEN_URL", "")
    if not token_url:
        die("OAuth2 selected but no token endpoint URL was provided.")

    def _req(form, extra):
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        headers.update(extra)
        r = urllib.request.Request(token_url, data=urllib.parse.urlencode(form).encode(),
                                   headers=headers, method="POST")
        with urllib.request.urlopen(r, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))

    body = {"grant_type": "client_credentials", "client_id": cid, "client_secret": csec}
    if os.environ.get("T_SCOPE"):
        body["scope"] = os.environ["T_SCOPE"]
    try:
        try:
            tok = _req(body, {})                                   # client_secret_post
        except urllib.error.HTTPError as e:
            if e.code not in (400, 401):
                raise
            basic = base64.b64encode(("%s:%s" % (cid, csec)).encode()).decode()
            b2 = {"grant_type": "client_credentials"}
            if os.environ.get("T_SCOPE"):
                b2["scope"] = os.environ["T_SCOPE"]
            tok = _req(b2, {"Authorization": "Basic " + basic})     # client_secret_basic
    except urllib.error.HTTPError as e:
        body_txt = ""
        try:
            body_txt = e.read().decode("utf-8")
        except Exception:
            pass
        die("OAuth2 token request was rejected (HTTP %d) — check the token URL, client ID, "
            "and client secret." % e.code, body_txt)
    except urllib.error.URLError as e:
        die("Could not reach the OAuth2 token endpoint — check the token URL and the "
            "in-enclave network path.", str(e.reason))
    if "access_token" not in tok:
        die("The token endpoint did not return an access_token — is it an OAuth2 "
            "client-credentials endpoint?", json.dumps(tok))
    return tok["access_token"]


def _auth_headers():
    mode = os.environ.get("T_AUTH", "none")
    if mode == "bearer":
        if not os.environ.get("T_KEY"):
            die("Bearer auth selected but no token was provided.")
        return {"Authorization": "Bearer " + os.environ["T_KEY"]}
    if mode == "basic":
        raw = ("%s:%s" % (os.environ.get("T_CID", ""), os.environ.get("T_CSEC", ""))).encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    if mode == "header":
        return {os.environ.get("T_IDH", "X-Client-Id"): os.environ.get("T_CID", ""),
                os.environ.get("T_SECH", "X-Client-Secret"): os.environ.get("T_CSEC", "")}
    if mode == "oauth2":
        return {"Authorization": "Bearer " + _oauth_token()}
    return {}


def _parse_verdict(s):
    try:
        i = s.index("{")
        depth = 0
        obj = None
        for j in range(i, len(s)):
            if s[j] == "{":
                depth += 1
            elif s[j] == "}":
                depth -= 1
                if depth == 0:
                    obj = json.loads(s[i:j + 1])
                    break
        if obj is None or obj.get("decision") not in ("PASS", "REVIEW", "BLOCK"):
            return None
        return obj
    except Exception:
        return None


def main():
    url, model = os.environ.get("T_URL", ""), os.environ.get("T_MODEL", "")
    if not url or not model:
        die("Inference API URL and model name are both required.")

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers.update(_auth_headers())   # may exit with a specific OAuth2 reason

    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": _prompt()},
            {"role": "user", "content": "<CONTENT>\nAll-hands meeting is on Thursday at "
                                        "3pm in the main hall.\n</CONTENT>"},
        ],
        "temperature": 0, "max_tokens": 256, "stream": False,
    }).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8")
        except Exception:
            pass
        if e.code in (401, 403):
            die("Authentication was rejected by the inference API (HTTP %d) — the credentials "
                "or the chosen auth mechanism are wrong for this endpoint." % e.code, detail)
        if e.code == 404:
            die("The inference API URL returned 404 — check the path (it should be the "
                "OpenAI-compatible /v1/chat/completions endpoint).", detail)
        die("The inference API returned HTTP %d to the chat-completions request." % e.code, detail)
    except urllib.error.URLError as e:
        die("Could not reach the inference API URL — check the URL, port, and the in-enclave "
            "network path (and TLS, if https).", str(e.reason))
    except Exception as e:
        die("The request to the inference API failed.", str(e))

    try:
        payload = json.loads(raw)
    except ValueError:
        die("The endpoint responded but not with JSON — it does not look like an "
            "OpenAI-compatible API.", raw)
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        die("The JSON response has no choices[0].message.content — this is not the OpenAI "
            "chat-completions response shape.", json.dumps(payload))

    verdict = _parse_verdict(content)
    if verdict is None:
        die("The model replied, but not with the required JSON verdict (a decision of "
            "PASS/REVIEW/BLOCK). The endpoint is reachable but the model/prompt are not "
            "producing a parseable verdict — check the model and that it honours the "
            "system prompt's output contract.", content)

    print("OK: reachable, OpenAI-compatible, returned a parseable verdict (decision=%s)."
          % verdict["decision"])
    sys.exit(0)


if __name__ == "__main__":
    main()
