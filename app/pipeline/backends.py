"""Stage 2 (Prompt Guard 2) and stage 3 (inspector LLM) backends.

Each stage has two interchangeable implementations selected by MODEL_BACKEND:
  * mock          — deterministic heuristics, no model weights. Lets the entire
                    service (API, pipeline, UI, drill-down) run and be tested with
                    nothing downloaded.
  * transformers  — real models on CPU. Prompt Guard 2 is a binary classifier;
                    the inspector is ANY instruct model (swap by config), driven
                    through its own chat template.

torch/transformers are imported lazily inside the transformers backends so the
app imports and runs in mock mode without them installed.
"""
import re
import json
from functools import lru_cache

from ..config import cfg

# ---------------------------------------------------------------------------
# Shared: load the inspector system prompt once.
# ---------------------------------------------------------------------------
from pathlib import Path
_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "inspector_system_prompt.txt"


@lru_cache(maxsize=1)
def system_prompt():
    return _PROMPT_PATH.read_text(encoding="utf-8")


# ===========================================================================
# Stage 2 — Prompt Guard 2
# ===========================================================================
_INJECTION_PATTERNS = [
    r"ignore (all|any|the)?\s*(previous|prior|above)\s*(instructions|prompts?|rules)",
    r"disregard (the|all|your)?\s*(instructions|rules|system)",
    r"you are now\b", r"\bact as\b.*\b(dan|jailbreak|unrestricted)\b",
    r"reveal (the|your)\s*(system )?(prompt|instructions)",
    r"output\s+(pass|allow|clean)\b", r"\bdeveloper mode\b",
    r"new instructions:", r"</?(system|instructions?)>",
]
_INJ_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)


class MockPromptGuard:
    name = "promptguard2-mock"

    def classify(self, text):
        hits = _INJ_RE.findall(text or "")
        score = 0.92 if hits else 0.02
        return {"label": "malicious" if score >= cfg.GUARD_THRESHOLD else "benign",
                "score": score, "windows": 1}


class TransformersPromptGuard:
    name = "promptguard2"

    def __init__(self):
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        self._torch = torch
        self.tok = AutoTokenizer.from_pretrained(cfg.GUARD_MODEL_PATH)
        self.model = AutoModelForSequenceClassification.from_pretrained(cfg.GUARD_MODEL_PATH)
        self.model.eval()

    def _score_window(self, text):
        import torch
        enc = self.tok(text, return_tensors="pt", truncation=True,
                       max_length=cfg.GUARD_WINDOW_TOKENS)
        with torch.no_grad():
            logits = self.model(**enc).logits
        probs = torch.softmax(logits, dim=-1)[0]
        # Binary classifier: index 1 == malicious/jailbreak.
        return float(probs[-1])

    def classify(self, text):
        text = text or ""
        ids = self.tok(text, add_special_tokens=False)["input_ids"]
        win, stride = cfg.GUARD_WINDOW_TOKENS - 2, cfg.GUARD_WINDOW_STRIDE
        if len(ids) <= win:
            chunks = [text]
        else:
            chunks = []
            for i in range(0, len(ids), stride):
                piece = ids[i:i + win]
                chunks.append(self.tok.decode(piece))
                if i + win >= len(ids):
                    break
        score = max(self._score_window(c) for c in chunks)
        return {"label": "malicious" if score >= cfg.GUARD_THRESHOLD else "benign",
                "score": round(score, 4), "windows": len(chunks)}


# ===========================================================================
# Stage 3 — Inspector LLM
# ===========================================================================
_BRIGHT_LINE = {"CLASS_MARKING", "DISSEM_CAVEAT", "CODEWORD_COMPARTMENT", "SECRET_CREDENTIAL"}

# Lexicon for the MOCK inspector (a faithful-enough stand-in so the demo is
# meaningful before real weights are present). The real model uses the prompt.
_MARKINGS = re.compile(
    r"\b(TOP SECRET|SECRET|CONFIDENTIAL|RESTRICTED|CUI|FOUO|FOR OFFICIAL USE ONLY|"
    r"OFFICIAL[- ]SENSITIVE|COSMIC TOP SECRET|NATO (SECRET|CONFIDENTIAL|RESTRICTED)|"
    r"RESTREINT UE|DISTRIBUTION STATEMENT [B-F]|EXPORT CONTROLLED)\b")
_CAVEATS = re.compile(r"\b(NOFORN|ORCON|PROPIN|IMCON|RELIDO|REL TO|EYES ONLY|EXDIS|NODIS)\b")
_CODEWORDS = re.compile(r"\b(TALENT KEYHOLE|KLONDIKE|GAMMA|BYEMAN|\bSI/TK\b)\b")
_PII = re.compile(
    r"\b(\d{3}-\d{2}-\d{4}|[STFG]\d{7}[A-Z]|\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b)\b")  # SSN/NRIC/card
_SECRET = re.compile(r"-----BEGIN [A-Z ]+-----|\b(api[_-]?key|password|passwd|secret)\b\s*[:=]",
                     re.IGNORECASE)


def _sev_rank(s):
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}[s]


def _decide(categories, injection):
    if not categories and not injection:
        return "PASS", "NONE"
    codes = {c["code"] for c in categories}
    if codes & _BRIGHT_LINE:
        return "BLOCK", "HIGH"
    if any(_sev_rank(c["severity"]) == 3 for c in categories):
        return "BLOCK", "HIGH"
    if injection and categories:
        return "BLOCK", "HIGH"
    if categories:
        top = max((c["severity"] for c in categories), key=_sev_rank)
        return "REVIEW", top
    return "REVIEW", "LOW"  # injection alone


def parse_verdict(raw):
    """Robust JSON extraction with fail-closed semantics: an unparseable or
    non-conformant verdict is treated as BLOCK, never PASS. Shared by the local
    (transformers) and remote (api) inspectors so the quantization contract — only
    the structured verdict crosses on, never the model's free text — is identical."""
    try:
        start = raw.index("{")
        depth = 0
        for i in range(start, len(raw)):
            if raw[i] == "{":
                depth += 1
            elif raw[i] == "}":
                depth -= 1
                if depth == 0:
                    obj = json.loads(raw[start:i + 1])
                    break
        else:
            raise ValueError("no balanced JSON object")
        cats = obj.get("categories") or []
        cats = [c for c in cats if isinstance(c, dict) and c.get("code")]
        decision = obj.get("decision")
        if decision not in ("PASS", "REVIEW", "BLOCK"):
            raise ValueError("bad decision")
        return {"schema_version": "3.0", "decision": decision,
                "risk_tier": obj.get("risk_tier", "NONE"), "categories": cats,
                "injection_attempt_detected": bool(obj.get("injection_attempt_detected")),
                "policy_conformant": bool(obj.get("policy_conformant", not cats)),
                "assessable": bool(obj.get("assessable", True))}
    except Exception as e:
        return {"schema_version": "3.0", "decision": "BLOCK", "risk_tier": "HIGH",
                "categories": [{"code": "PARSE_ERROR", "severity": "HIGH", "occurrences": "1"}],
                "injection_attempt_detected": False, "policy_conformant": False,
                "assessable": False, "_parse_error": str(e)}


class MockInspector:
    name = "inspector-mock"

    def inspect(self, text):
        text = text or ""
        cats = []

        def add(code, sev):
            cats.append({"code": code, "severity": sev, "occurrences": "1"})

        if _MARKINGS.search(text):
            add("CLASS_MARKING", "HIGH")
        if _CAVEATS.search(text):
            add("DISSEM_CAVEAT", "HIGH")
        if _CODEWORDS.search(text):
            add("CODEWORD_COMPARTMENT", "HIGH")
        if _SECRET.search(text):
            add("SECRET_CREDENTIAL", "HIGH")
        if _PII.search(text):
            add("PII", "MEDIUM")
        injection = bool(_INJ_RE.search(text))
        decision, tier = _decide(cats, injection)
        return {"schema_version": "3.0", "decision": decision, "risk_tier": tier,
                "categories": cats, "injection_attempt_detected": injection,
                "policy_conformant": not cats, "assessable": True}


class TransformersInspector:
    name = "inspector"

    def __init__(self):
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM
        self._torch = torch
        dtype = {"float32": torch.float32, "float16": torch.float16,
                 "bfloat16": torch.bfloat16}.get(cfg.REVIEW_DTYPE, torch.float32)
        self.tok = AutoTokenizer.from_pretrained(cfg.REVIEW_MODEL_PATH)
        self.model = AutoModelForCausalLM.from_pretrained(
            cfg.REVIEW_MODEL_PATH, torch_dtype=dtype, low_cpu_mem_usage=True)
        self.model.eval()

    def _build_inputs(self, content):
        """Model-agnostic prompt assembly via the tokenizer's own chat template.
        Falls back to folding the system prompt into the first user turn for models
        without a system role."""
        user = "<CONTENT>\n%s\n</CONTENT>" % content
        messages = [{"role": "system", "content": system_prompt()},
                    {"role": "user", "content": user}]
        kwargs = {}
        # Qwen3 etc. accept enable_thinking; keep it off for latency when supported.
        try:
            return self.tok.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True,
                enable_thinking=cfg.REVIEW_THINKING)
        except TypeError:
            pass
        try:
            return self.tok.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True)
        except Exception:
            # No system role support — fold into the first user message.
            folded = [{"role": "user", "content": system_prompt() + "\n\n" + user}]
            try:
                return self.tok.apply_chat_template(
                    folded, tokenize=False, add_generation_prompt=True)
            except Exception:
                return system_prompt() + "\n\n" + user + "\n"

    def inspect(self, text):
        import torch
        content = (text or "")[: cfg.REVIEW_CTX_CHARS]
        prompt = self._build_inputs(content)
        enc = self.tok(prompt, return_tensors="pt")
        pad_id = self.tok.pad_token_id
        if pad_id is None:
            pad_id = self.tok.eos_token_id
        with torch.no_grad():
            out = self.model.generate(
                **enc, max_new_tokens=cfg.REVIEW_MAXTOK, do_sample=False,
                pad_token_id=pad_id)
        gen = out[0][enc["input_ids"].shape[1]:]
        raw = self.tok.decode(gen, skip_special_tokens=True)
        return parse_verdict(raw)


class ApiInspector:
    """Inspector served by a remote OpenAI-compatible chat-completions endpoint
    (vLLM / TGI / Ollama / llama.cpp server / LocalAI). It sends the same system
    prompt and content as the local backend; the response is parsed into the
    quantized verdict high-side, so only the verdict — never the model's free
    text — flows on. Fail-closed if the endpoint is unreachable or the envelope
    is malformed (the inspector is advisory and human review is mandatory, so this
    routes to review rather than silently passing).

    Auth (INSPECTOR_API_AUTH): none | bearer | basic | header | oauth2.
      * bearer  — Authorization: Bearer <INSPECTOR_API_KEY>
      * basic   — Authorization: Basic base64(client_id:client_secret)
      * header  — <ID_HEADER>: client_id  and  <SECRET_HEADER>: client_secret
      * oauth2  — client-credentials: fetch a bearer token from INSPECTOR_API_TOKEN_URL
                  (tries client_secret_post, falls back to client_secret_basic),
                  cache it until expiry, and refresh once on a 401.

    Architectural notes for accreditation:
      * The endpoint MUST be inside the same high-side enclave — document content
        is sent to it; this is an in-domain call, not a cross-domain egress.
      * Prompt Guard 2 still runs *before* this stage, unchanged; moving inference
        to an API does not alter the injection shield or the security boundary.
      * Uses only the standard library — no extra wheel in the offline bundle.
    """
    name = "inspector-api"

    def __init__(self):
        if not cfg.INSPECTOR_API_URL or not cfg.INSPECTOR_API_MODEL:
            raise RuntimeError(
                "INSPECTOR_BACKEND=api requires INSPECTOR_API_URL and INSPECTOR_API_MODEL")
        self.url = cfg.INSPECTOR_API_URL
        self.model = cfg.INSPECTOR_API_MODEL
        self._token = None
        self._token_exp = 0.0

    def _fetch_token(self):
        """OAuth2 client-credentials: client_secret_post, falling back to _basic."""
        import time, base64, urllib.request, urllib.parse, urllib.error
        cid, csec = cfg.INSPECTOR_API_CLIENT_ID, cfg.INSPECTOR_API_CLIENT_SECRET

        def _req(form, extra):
            headers = {"Content-Type": "application/x-www-form-urlencoded",
                       "Accept": "application/json"}
            headers.update(extra)
            r = urllib.request.Request(cfg.INSPECTOR_API_TOKEN_URL,
                                       data=urllib.parse.urlencode(form).encode(),
                                       headers=headers, method="POST")
            with urllib.request.urlopen(r, timeout=cfg.INSPECTOR_API_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))

        body = {"grant_type": "client_credentials", "client_id": cid, "client_secret": csec}
        if cfg.INSPECTOR_API_SCOPE:
            body["scope"] = cfg.INSPECTOR_API_SCOPE
        try:
            tok = _req(body, {})                                   # client_secret_post
        except urllib.error.HTTPError as e:
            if e.code not in (400, 401):
                raise
            basic = base64.b64encode(("%s:%s" % (cid, csec)).encode()).decode()
            body2 = {"grant_type": "client_credentials"}
            if cfg.INSPECTOR_API_SCOPE:
                body2["scope"] = cfg.INSPECTOR_API_SCOPE
            tok = _req(body2, {"Authorization": "Basic " + basic})  # client_secret_basic
        self._token = tok["access_token"]
        self._token_exp = time.time() + int(tok.get("expires_in", 300)) - 30
        return self._token

    def _bearer(self, force=False):
        import time
        if not force and self._token and time.time() < self._token_exp:
            return self._token
        return self._fetch_token()

    def _auth_headers(self, force_token=False):
        import base64
        mode = cfg.INSPECTOR_API_AUTH
        if mode == "bearer" and cfg.INSPECTOR_API_KEY:
            return {"Authorization": "Bearer " + cfg.INSPECTOR_API_KEY}
        if mode == "basic":
            raw = ("%s:%s" % (cfg.INSPECTOR_API_CLIENT_ID, cfg.INSPECTOR_API_CLIENT_SECRET)).encode()
            return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
        if mode == "header":
            return {cfg.INSPECTOR_API_ID_HEADER: cfg.INSPECTOR_API_CLIENT_ID,
                    cfg.INSPECTOR_API_SECRET_HEADER: cfg.INSPECTOR_API_CLIENT_SECRET}
        if mode == "oauth2":
            return {"Authorization": "Bearer " + self._bearer(force=force_token)}
        return {}

    def _post_chat(self, body, force_token=False):
        import urllib.request
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers.update(self._auth_headers(force_token=force_token))
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=cfg.INSPECTOR_API_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return payload["choices"][0]["message"]["content"]

    def inspect(self, text):
        import urllib.error
        content = (text or "")[: cfg.REVIEW_CTX_CHARS]
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt()},
                {"role": "user", "content": "<CONTENT>\n%s\n</CONTENT>" % content},
            ],
            "temperature": 0,
            "max_tokens": cfg.REVIEW_MAXTOK,
            "stream": False,
        }).encode("utf-8")
        try:
            raw = self._post_chat(body)
        except urllib.error.HTTPError as e:
            if e.code == 401 and cfg.INSPECTOR_API_AUTH == "oauth2":
                try:
                    raw = self._post_chat(body, force_token=True)   # refresh token + retry once
                except Exception as e2:
                    return self._failed(e2)
            else:
                return self._failed(e)
        except Exception as e:
            return self._failed(e)
        return parse_verdict(raw)

    @staticmethod
    def _failed(e):
        return {"schema_version": "3.0", "decision": "BLOCK", "risk_tier": "HIGH",
                "categories": [{"code": "PARSE_ERROR", "severity": "HIGH", "occurrences": "1"}],
                "injection_attempt_detected": False, "policy_conformant": False,
                "assessable": False, "_api_error": str(e)}


# ===========================================================================
# Factory — built once and reused by the worker.
# ===========================================================================
@lru_cache(maxsize=1)
def get_stages():
    guard = TransformersPromptGuard() if cfg.GUARD_BACKEND == "transformers" else MockPromptGuard()
    if cfg.INSPECTOR_BACKEND == "transformers":
        inspector = TransformersInspector()
    elif cfg.INSPECTOR_BACKEND == "api":
        inspector = ApiInspector()
    else:
        inspector = MockInspector()
    return guard, inspector
