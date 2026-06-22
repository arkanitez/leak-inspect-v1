"""FastAPI application: API + server-rendered console for the three-stage
inspection pipeline (charguard -> Prompt Guard 2 -> inspector)."""
import os
import json
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import db, worker
from .config import cfg
from .auth import require_auth
from .parsing.extract import extract
from .pipeline.locators import locate, merge_spans
from .schemas import JobSummary, JobStatus, ItemDetail, JobList

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")

WEB = Path(__file__).resolve().parent / "web"
SEG_DIR = cfg.DATA_DIR / "segments"


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg.ensure_dirs()
    SEG_DIR.mkdir(parents=True, exist_ok=True)
    db.init_db()
    worker.start()
    log.info("backend=%s  inspector=%s  guard_threshold=%.2f",
             cfg.MODEL_BACKEND, cfg.REVIEW_MODEL_PATH, cfg.GUARD_THRESHOLD)
    yield


app = FastAPI(title="Whitelist Inspection Pipeline",
              description="Upload text or documents; each is inspected by charguard → "
                          "Prompt Guard 2 → an LLM inspector and given a verdict.",
              version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(WEB / "static")), name="static")
templates = Jinja2Templates(directory=str(WEB / "templates"))


# ===========================================================================
# Ingestion (runs off the event loop)
# ===========================================================================
def _ingest_job(name, blobs, texts):
    total = 0
    n_files = len(blobs)
    if n_files > cfg.MAX_FILES_PER_JOB:
        raise HTTPException(413, "too many files (max %d)" % cfg.MAX_FILES_PER_JOB)

    jid = db.create_job(name=name or None)
    seq = 0

    def persist(kind, source_name, data):
        nonlocal seq, total
        total += len(data)
        if total > cfg.MAX_JOB_BYTES:
            raise HTTPException(413, "job exceeds size cap")
        fmt, segments, note = extract(source_name, data)
        chars = sum(len(s["text"]) for s in segments)
        iid = db.add_item(jid, seq, kind, source_name, fmt, len(data),
                          extracted_chars=chars, segment_count=len(segments),
                          status="PENDING")
        raw_path = str(cfg.UPLOAD_DIR / iid)
        with open(raw_path, "wb") as fh:
            fh.write(data)
        seg_path = str(SEG_DIR / (iid + ".json"))
        with open(seg_path, "w", encoding="utf-8") as fh:
            json.dump({"segments": segments, "note": note}, fh, ensure_ascii=False)
        db.set_item(iid, raw_path=raw_path, seg_path=seg_path)
        seq += 1

    for blob in blobs:
        fname, data = blob
        if len(data) > cfg.MAX_FILE_BYTES:
            raise HTTPException(413, "file '%s' exceeds size cap" % fname)
        persist("DOCUMENT", fname, data)

    for i, t in enumerate(texts, 1):
        data = t.encode("utf-8")
        if len(data) > cfg.MAX_TEXT_BYTES:
            raise HTTPException(413, "text chunk %d exceeds size cap" % i)
        persist("TEXT", "text-chunk-%d" % i, data)

    if seq == 0:
        raise HTTPException(400, "nothing to inspect — provide text and/or files")
    return jid


def _job_summary(jid) -> dict:
    job = db.get_job(jid)
    if not job:
        raise HTTPException(404, "job not found")
    items = db.list_items(jid)
    return {
        "id": job["id"], "name": job["name"], "status": job["status"],
        "decision": job["decision"], "created_at": job["created_at"],
        "item_count": len(items), "total_bytes": sum(i["size_bytes"] for i in items),
        "items": [{
            "id": i["id"], "seq": i["seq"], "kind": i["kind"],
            "source_name": i["source_name"], "fmt": i["fmt"], "size_bytes": i["size_bytes"],
            "extracted_chars": i["extracted_chars"], "segment_count": i["segment_count"],
            "status": i["status"],
        } for i in items],
    }


# ===========================================================================
# API
# ===========================================================================
@app.get("/api/health", tags=["meta"])
def health():
    insp_model = cfg.REVIEW_MODEL_PATH
    if cfg.INSPECTOR_BACKEND == "api":
        insp_model = cfg.INSPECTOR_API_MODEL or "api"
    return {"status": "ok", "backend": cfg.MODEL_BACKEND,
            "guard_backend": cfg.GUARD_BACKEND, "inspector_backend": cfg.INSPECTOR_BACKEND,
            "inspector_model": insp_model, "guard_model": cfg.GUARD_MODEL_PATH}


@app.post("/api/jobs", response_model=JobSummary, tags=["jobs"])
async def create_job(name: Optional[str] = Form(default=None),
                     files: List[UploadFile] = File(default=[]),
                     texts: List[str] = Form(default=[]),
                     _=Depends(require_auth)):
    """Create a DRAFT job from uploaded files and/or text chunks. Returns the
    stocktake summary. Nothing is inspected until you call /confirm."""
    blobs = [(f.filename or "upload", await f.read()) for f in files]
    texts = [t for t in texts if t and t.strip()]
    jid = await asyncio.to_thread(_ingest_job, name, blobs, texts)
    return _job_summary(jid)


def _job_label(j):
    if j.get("name"):
        return j["name"]
    first = j.get("first_source") or "inspection"
    n = j.get("item_count") or 0
    return first + (" +%d more" % (n - 1) if n > 1 else "")


@app.get("/api/jobs", response_model=JobList, tags=["jobs"])
def list_jobs_api(_=Depends(require_auth)):
    """All jobs, split into in-progress (queued/running) and completed (done/error)."""
    inprog, done = [], []
    for j in db.list_jobs():
        entry = {
            "id": j["id"], "label": _job_label(j), "name": j["name"],
            "status": j["status"], "decision": j["decision"],
            "created_at": j["created_at"], "confirmed_at": j["confirmed_at"],
            "completed_at": j["completed_at"],
            "item_count": j["item_count"] or 0, "done": j["done_count"] or 0,
        }
        (inprog if j["status"] in ("QUEUED", "RUNNING") else done).append(entry)
    return {"in_progress": inprog, "completed": done}


@app.get("/api/jobs/{jid}", response_model=JobSummary, tags=["jobs"])
def job_summary(jid: str, _=Depends(require_auth)):
    """Stocktake: the documents/text in a job before (or after) inspection."""
    return _job_summary(jid)


@app.post("/api/jobs/{jid}/confirm", response_model=JobStatus, tags=["jobs"])
def confirm_job(jid: str, _=Depends(require_auth)):
    """Confirm the upload and start inspection (enqueues every item)."""
    job = db.get_job(jid)
    if not job:
        raise HTTPException(404, "job not found")
    if job["status"] != "DRAFT":
        raise HTTPException(409, "job already confirmed (status=%s)" % job["status"])
    db.set_job(jid, status="QUEUED", confirmed_at=db.now())
    for it in db.list_items(jid):
        worker.enqueue(it["id"])
    return _job_status(jid)


def _job_status(jid) -> dict:
    job = db.get_job(jid)
    if not job:
        raise HTTPException(404, "job not found")
    items = db.list_items(jid)
    # Reflect overall running state.
    if job["status"] == "QUEUED" and any(i["status"] == "RUNNING" for i in items):
        db.set_job(jid, status="RUNNING")
        job["status"] = "RUNNING"
    done, total = db.job_progress(jid)
    return {
        "id": jid, "status": job["status"], "decision": job["decision"],
        "done": done, "total": total,
        "items": [{"id": i["id"], "seq": i["seq"], "source_name": i["source_name"],
                   "status": i["status"], "decision": i["decision"],
                   "risk_tier": i["risk_tier"]} for i in items],
    }


@app.get("/api/jobs/{jid}/status", response_model=JobStatus, tags=["jobs"])
def job_status(jid: str, _=Depends(require_auth)):
    """Live status: per-item progress and verdicts as they complete (poll this)."""
    return _job_status(jid)


@app.get("/api/jobs/{jid}/results", response_model=JobStatus, tags=["jobs"])
def job_results(jid: str, _=Depends(require_auth)):
    """Final results: same shape as status; meaningful once status is DONE."""
    return _job_status(jid)


# ---------------------------------------------------------------------------
# Evidence: map findings back to the original segment text + spans to highlight.
# Highlighting is tied to inspector findings; secret/PII spans are masked and the
# cleartext is withheld until an explicit, audited reveal request.
# ---------------------------------------------------------------------------
def _segment_evidence(it, findings):
    """provenance -> {"text": str, "spans": [(start,end,mask,code)]} for every
    segment that has an INSPECTOR or PROMPTGUARD finding. Spans come only from
    inspector findings; promptguard-only segments get text and no spans.
    Charguard findings already carry verbatim, so charguard-only segments are skipped."""
    codes_by_prov, show = {}, set()
    for f in findings:
        prov = f.get("provenance")
        if not prov:
            continue
        if f["stage"] == "INSPECTOR":
            codes_by_prov.setdefault(prov, []).append(f["code"])
            show.add(prov)
        elif f["stage"] == "PROMPTGUARD":
            show.add(prov)
    if not show:
        return {}
    try:
        with open(it["seg_path"], encoding="utf-8") as fh:
            cached = json.load(fh).get("segments", [])
    except (OSError, json.JSONDecodeError, TypeError):
        cached = []
    out = {}
    for seg in cached:
        prov = seg.get("provenance")
        if prov not in show or prov in out:
            continue
        text = seg.get("text", "")
        raw = []
        for code in codes_by_prov.get(prov, ()):
            raw.extend(locate(code, text))
        out[prov] = {"text": text, "spans": merge_spans(raw)}
    return out


def _parts_from(text, spans):
    """Tokenize text into plain/hl/mask parts. Mask parts carry only an index
    (mid) — never the cleartext, which the reveal endpoint serves on demand."""
    parts, pos, mid = [], 0, 0
    for s, e, mask, code in spans:
        if s > pos:
            parts.append({"kind": "plain", "t": text[pos:s]})
        if mask:
            parts.append({"kind": "mask", "code": code, "mid": mid})
            mid += 1
        else:
            parts.append({"kind": "hl", "t": text[s:e], "code": code})
        pos = e
    if pos < len(text):
        parts.append({"kind": "plain", "t": text[pos:]})
    return parts


@app.get("/api/jobs/{jid}/items/{iid}", response_model=ItemDetail, tags=["items"])
def item_detail(jid: str, iid: str, _=Depends(require_auth)):
    """Drill-down for one item: every finding, why it was flagged, the captured
    content (deterministic stages), and the original segment text with the spans
    behind each inspector finding highlighted (secrets/PII masked)."""
    it = db.get_item(iid)
    if not it or it["job_id"] != jid:
        raise HTTPException(404, "item not found")
    findings = db.list_findings(iid)
    ev = _segment_evidence(it, findings)
    segments = [{"provenance": prov, "parts": _parts_from(d["text"], d["spans"])}
                for prov, d in ev.items()]
    return {
        "id": it["id"], "seq": it["seq"], "source_name": it["source_name"],
        "fmt": it["fmt"], "kind": it["kind"], "status": it["status"],
        "decision": it["decision"], "risk_tier": it["risk_tier"],
        "stages": json.loads(it["stages_json"]) if it["stages_json"] else {},
        "findings": findings, "segments": segments,
    }


@app.get("/api/jobs/{jid}/items/{iid}/reveal", include_in_schema=False)
def reveal_span(jid: str, iid: str, prov: str, mid: int, _=Depends(require_auth)):
    """Return the cleartext of a single masked span. Deterministic re-location
    keeps the index stable with the drill-down. Logged for audit."""
    it = db.get_item(iid)
    if not it or it["job_id"] != jid:
        raise HTTPException(404, "item not found")
    seg = _segment_evidence(it, db.list_findings(iid)).get(prov)
    if not seg:
        raise HTTPException(404, "segment not found")
    masked = [(s, e) for (s, e, m, _c) in seg["spans"] if m]
    if mid < 0 or mid >= len(masked):
        raise HTTPException(404, "span not found")
    s, e = masked[mid]
    log.info("reveal: item=%s provenance=%r mid=%d", iid, prov, mid)
    return {"value": seg["text"][s:e]}


# ===========================================================================
# UI (server-rendered shells; data via the API above)
# ===========================================================================
@app.get("/", response_class=HTMLResponse, tags=["ui"], include_in_schema=False)
def ui_index(request: Request, _=Depends(require_auth)):
    return templates.TemplateResponse(request, "index.html", {"cfg": cfg})


@app.get("/jobs", response_class=HTMLResponse, include_in_schema=False)
def ui_jobs(request: Request, _=Depends(require_auth)):
    return templates.TemplateResponse(request, "jobs.html", {})


@app.get("/jobs/{jid}", response_class=HTMLResponse, include_in_schema=False)
def ui_job(request: Request, jid: str, _=Depends(require_auth)):
    return templates.TemplateResponse(request, "job.html", {"jid": jid})


@app.get("/jobs/{jid}/monitor", response_class=HTMLResponse, include_in_schema=False)
def ui_monitor(request: Request, jid: str, _=Depends(require_auth)):
    return templates.TemplateResponse(request, "monitor.html", {"jid": jid})


@app.get("/jobs/{jid}/results", response_class=HTMLResponse, include_in_schema=False)
def ui_results(request: Request, jid: str, _=Depends(require_auth)):
    return templates.TemplateResponse(request, "results.html", {"jid": jid})


@app.get("/jobs/{jid}/items/{iid}", response_class=HTMLResponse, include_in_schema=False)
def ui_item(request: Request, jid: str, iid: str, _=Depends(require_auth)):
    return templates.TemplateResponse(request, "item.html", {"jid": jid, "iid": iid})
