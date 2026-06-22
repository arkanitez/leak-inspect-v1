"""Central configuration. Everything is environment-driven so the same code
runs as the AWS demo (mock or small CPU model) and the air-gapped production
deployment (whatever instruct model that environment provides)."""
import os
from pathlib import Path


def _b(name, default):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _i(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


class Config:
    # --- storage (writable; defaults to a local dir so it runs anywhere) ---
    DATA_DIR = Path(os.getenv("DATA_DIR", str(Path.home() / ".whitelist-demo"))).resolve()
    DB_PATH = Path(os.getenv("DB_PATH", "")) if os.getenv("DB_PATH") else DATA_DIR / "demo.db"
    UPLOAD_DIR = DATA_DIR / "uploads"

    # --- hostile-input caps (parsing untrusted documents) ---
    MAX_FILE_BYTES = _i("MAX_FILE_BYTES", 25 * 1024 * 1024)      # 25 MiB per file
    MAX_JOB_BYTES = _i("MAX_JOB_BYTES", 100 * 1024 * 1024)       # 100 MiB per job
    MAX_FILES_PER_JOB = _i("MAX_FILES_PER_JOB", 50)
    MAX_TEXT_BYTES = _i("MAX_TEXT_BYTES", 2 * 1024 * 1024)       # 2 MiB per text chunk
    PARSE_TIMEOUT_S = _i("PARSE_TIMEOUT_S", 30)
    MAX_DECOMPRESS_BYTES = _i("MAX_DECOMPRESS_BYTES", 200 * 1024 * 1024)  # zip-bomb guard
    MAX_ZIP_ENTRIES = _i("MAX_ZIP_ENTRIES", 5000)

    # --- pipeline behaviour ---
    SHORT_CIRCUIT = _b("SHORT_CIRCUIT", False)   # stop at first BLOCK stage if True
    SEGMENT_MARKERS = _b("SEGMENT_MARKERS", True)  # label provenance in inspector input

    # --- model backend ---
    # "mock" = deterministic heuristic stages, no weights required (default).
    # "transformers" = load real Prompt Guard 2 + instruct model on CPU.
    MODEL_BACKEND = os.getenv("MODEL_BACKEND", "mock").strip().lower()
    # Per-stage override (each defaults to MODEL_BACKEND). Lets you keep Prompt
    # Guard 2 local while serving the inspector from a remote inference API.
    GUARD_BACKEND = os.getenv("GUARD_BACKEND", MODEL_BACKEND).strip().lower()
    INSPECTOR_BACKEND = os.getenv("INSPECTOR_BACKEND", MODEL_BACKEND).strip().lower()

    # Prompt Guard 2 (stage 2).
    GUARD_MODEL_PATH = os.getenv("GUARD_MODEL_PATH", "meta-llama/Llama-Prompt-Guard-2-86M")
    GUARD_THRESHOLD = float(os.getenv("GUARD_THRESHOLD", "0.5"))
    GUARD_WINDOW_TOKENS = _i("GUARD_WINDOW_TOKENS", 512)
    GUARD_WINDOW_STRIDE = _i("GUARD_WINDOW_STRIDE", 448)

    # Inspector LLM (stage 3) — model-agnostic; swap by changing this path.
    REVIEW_MODEL_PATH = os.getenv("REVIEW_MODEL_PATH", "Qwen/Qwen3-4B-Instruct-2507")
    REVIEW_DTYPE = os.getenv("REVIEW_DTYPE", "float32")   # float32 for CPU
    REVIEW_MAXTOK = _i("REVIEW_MAXTOK", 256)              # sized to the verdict schema
    REVIEW_CTX_CHARS = _i("REVIEW_CTX_CHARS", 12000)      # truncate very long items
    REVIEW_THINKING = _b("REVIEW_THINKING", False)        # disable thinking for latency

    # Inspector via remote inference API (set INSPECTOR_BACKEND=api). Targets an
    # OpenAI-compatible /v1/chat/completions endpoint (vLLM / TGI / Ollama /
    # llama.cpp server / LocalAI). The endpoint MUST live inside the same high-side
    # enclave — document content is sent to it; only the parsed verdict is kept.
    INSPECTOR_API_URL = os.getenv("INSPECTOR_API_URL", "")        # full chat-completions URL
    INSPECTOR_API_MODEL = os.getenv("INSPECTOR_API_MODEL", "")    # model name the server serves
    INSPECTOR_API_TIMEOUT = _i("INSPECTOR_API_TIMEOUT", 120)
    # Auth mechanism: none | bearer | basic | header | oauth2 (client-credentials).
    INSPECTOR_API_AUTH = os.getenv("INSPECTOR_API_AUTH", "none").strip().lower()
    INSPECTOR_API_KEY = os.getenv("INSPECTOR_API_KEY", "")              # bearer: the token
    INSPECTOR_API_CLIENT_ID = os.getenv("INSPECTOR_API_CLIENT_ID", "")          # basic|header|oauth2
    INSPECTOR_API_CLIENT_SECRET = os.getenv("INSPECTOR_API_CLIENT_SECRET", "")  # basic|header|oauth2
    INSPECTOR_API_TOKEN_URL = os.getenv("INSPECTOR_API_TOKEN_URL", "")          # oauth2 token endpoint
    INSPECTOR_API_SCOPE = os.getenv("INSPECTOR_API_SCOPE", "")                  # oauth2 optional scope
    INSPECTOR_API_ID_HEADER = os.getenv("INSPECTOR_API_ID_HEADER", "X-Client-Id")          # header mode
    INSPECTOR_API_SECRET_HEADER = os.getenv("INSPECTOR_API_SECRET_HEADER", "X-Client-Secret")  # header mode

    # --- worker ---
    WORKER_POLL_S = float(os.getenv("WORKER_POLL_S", "0.25"))

    # --- retention ---
    RETAIN_ORIGINALS = _b("RETAIN_ORIGINALS", False)   # delete uploaded bytes after inspection
    JOB_TTL_HOURS = _i("JOB_TTL_HOURS", 24)

    # --- optional Keycloak OIDC (off for demo) ---
    AUTH_ENABLED = _b("AUTH_ENABLED", False)
    OIDC_ISSUER = os.getenv("OIDC_ISSUER", "")          # e.g. https://kc/realms/airgap
    OIDC_JWKS_URL = os.getenv("OIDC_JWKS_URL", "")      # defaults derived from issuer if blank
    OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", "")
    OIDC_ALGS = os.getenv("OIDC_ALGS", "RS256").split(",")

    @classmethod
    def ensure_dirs(cls):
        cls.DATA_DIR.mkdir(parents=True, exist_ok=True)
        cls.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


cfg = Config()
