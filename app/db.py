"""SQLite persistence for jobs, items, and findings.

Schema is intentionally small and durable. WAL mode lets the web threads read
while the single worker thread writes. We open a short-lived connection per
operation, which is safe across threads and cheap at demo scale.
"""
import sqlite3
import json
import time
import uuid
from contextlib import contextmanager
from .config import cfg

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    name         TEXT,
    status       TEXT NOT NULL,          -- DRAFT|QUEUED|RUNNING|DONE|ERROR
    decision     TEXT,                   -- aggregated: PASS|REVIEW|BLOCK
    created_at   REAL NOT NULL,
    confirmed_at REAL,
    completed_at REAL
);
CREATE TABLE IF NOT EXISTS items (
    id            TEXT PRIMARY KEY,
    job_id        TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    kind          TEXT NOT NULL,         -- TEXT|DOCUMENT
    source_name   TEXT NOT NULL,
    fmt           TEXT,                  -- txt|docx|xlsx|pptx|pdf|unsupported
    size_bytes    INTEGER NOT NULL,
    extracted_chars INTEGER DEFAULT 0,
    segment_count INTEGER DEFAULT 0,
    status        TEXT NOT NULL,         -- PENDING|QUEUED|RUNNING|DONE|ERROR|SKIPPED
    decision      TEXT,                  -- PASS|REVIEW|BLOCK
    risk_tier     TEXT,
    stages_json   TEXT,                  -- per-stage decisions summary
    error         TEXT,
    raw_path      TEXT,                  -- uploaded original bytes
    seg_path      TEXT,                  -- cached extracted segments (json)
    created_at    REAL NOT NULL,
    started_at    REAL,
    finished_at   REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    item_id     TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    stage       TEXT NOT NULL,          -- CHARGUARD|PROMPTGUARD|INSPECTOR
    code        TEXT NOT NULL,
    severity    TEXT NOT NULL,          -- LOW|MEDIUM|HIGH
    title       TEXT NOT NULL,          -- human-readable heading
    explanation TEXT,                   -- plain-English why-it-matters
    provenance  TEXT,                   -- where in the doc (body/header/comment/...)
    verbatim    TEXT,                   -- captured span (deterministic stages only)
    position    INTEGER,
    occurrences TEXT,
    created_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_job ON items(job_id);
CREATE INDEX IF NOT EXISTS idx_find_item ON findings(item_id);
"""


def now():
    return time.time()


def new_id():
    return uuid.uuid4().hex


@contextmanager
def conn():
    c = sqlite3.connect(str(cfg.DB_PATH), timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    cfg.ensure_dirs()
    with conn() as c:
        c.executescript(SCHEMA)


# ----------------------------------------------------------------------------
# Jobs
# ----------------------------------------------------------------------------
def create_job(name=None):
    jid = new_id()
    with conn() as c:
        c.execute("INSERT INTO jobs(id,name,status,created_at) VALUES(?,?,?,?)",
                  (jid, name, "DRAFT", now()))
    return jid


def get_job(jid):
    with conn() as c:
        r = c.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    return dict(r) if r else None


def set_job(jid, **fields):
    if not fields:
        return
    cols = ",".join(f"{k}=?" for k in fields)
    with conn() as c:
        c.execute(f"UPDATE jobs SET {cols} WHERE id=?", (*fields.values(), jid))


def list_jobs(exclude_draft=True, limit=500):
    """All jobs (most-recent first) with item/progress counts and a label hint.
    Excludes unconfirmed DRAFT jobs by default."""
    where = "WHERE j.status != 'DRAFT'" if exclude_draft else ""
    with conn() as c:
        rows = c.execute(f"""
            SELECT j.*,
                   COUNT(i.id) AS item_count,
                   SUM(CASE WHEN i.status IN ('DONE','ERROR','SKIPPED') THEN 1 ELSE 0 END) AS done_count,
                   (SELECT source_name FROM items WHERE job_id=j.id ORDER BY seq LIMIT 1) AS first_source
            FROM jobs j LEFT JOIN items i ON i.job_id = j.id
            {where}
            GROUP BY j.id
            ORDER BY COALESCE(j.confirmed_at, j.created_at) DESC
            LIMIT ?""", (limit,)).fetchall()
    return [dict(r) for r in rows]


# ----------------------------------------------------------------------------
# Items
# ----------------------------------------------------------------------------
def add_item(job_id, seq, kind, source_name, fmt, size_bytes, raw_path=None,
             seg_path=None, extracted_chars=0, segment_count=0, status="PENDING"):
    iid = new_id()
    with conn() as c:
        c.execute("""INSERT INTO items(id,job_id,seq,kind,source_name,fmt,size_bytes,
                     extracted_chars,segment_count,status,raw_path,seg_path,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (iid, job_id, seq, kind, source_name, fmt, size_bytes,
                   extracted_chars, segment_count, status, raw_path, seg_path, now()))
    return iid


def get_item(iid):
    with conn() as c:
        r = c.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()
    return dict(r) if r else None


def list_items(job_id):
    with conn() as c:
        rows = c.execute("SELECT * FROM items WHERE job_id=? ORDER BY seq", (job_id,)).fetchall()
    return [dict(r) for r in rows]


def set_item(iid, **fields):
    if not fields:
        return
    cols = ",".join(f"{k}=?" for k in fields)
    with conn() as c:
        c.execute(f"UPDATE items SET {cols} WHERE id=?", (*fields.values(), iid))


def queued_item_ids():
    with conn() as c:
        rows = c.execute("SELECT id FROM items WHERE status IN ('QUEUED','RUNNING') ORDER BY created_at").fetchall()
    return [r["id"] for r in rows]


# ----------------------------------------------------------------------------
# Findings
# ----------------------------------------------------------------------------
def add_finding(item_id, stage, code, severity, title, explanation=None,
                provenance=None, verbatim=None, position=None, occurrences=None):
    fid = new_id()
    with conn() as c:
        c.execute("""INSERT INTO findings(id,item_id,stage,code,severity,title,explanation,
                     provenance,verbatim,position,occurrences,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (fid, item_id, stage, code, severity, title, explanation,
                   provenance, verbatim, position, occurrences, now()))
    return fid


def list_findings(item_id):
    order = "CASE stage WHEN 'CHARGUARD' THEN 0 WHEN 'PROMPTGUARD' THEN 1 ELSE 2 END"
    sev = "CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END"
    with conn() as c:
        rows = c.execute(f"SELECT * FROM findings WHERE item_id=? ORDER BY {order},{sev}",
                         (item_id,)).fetchall()
    return [dict(r) for r in rows]


def clear_findings(item_id):
    with conn() as c:
        c.execute("DELETE FROM findings WHERE item_id=?", (item_id,))


# ----------------------------------------------------------------------------
# Aggregation helpers
# ----------------------------------------------------------------------------
_DECISION_RANK = {"PASS": 0, "REVIEW": 1, "BLOCK": 2}


def worst(decisions):
    """Aggregate a list of decisions: any BLOCK -> BLOCK, any REVIEW -> REVIEW."""
    best = "PASS"
    for d in decisions:
        if d and _DECISION_RANK.get(d, 0) > _DECISION_RANK[best]:
            best = d
    return best


def job_progress(job_id):
    items = list_items(job_id)
    done = sum(1 for i in items if i["status"] in ("DONE", "ERROR", "SKIPPED"))
    return done, len(items)
