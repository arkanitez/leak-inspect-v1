"""Per-item pipeline: every segment passes charguard -> Prompt Guard 2 -> inspector.

Running per-segment means each gate's findings carry the segment's provenance (which
header/comment/note/body the content came from), not just charguard's. charguard still
runs first within each segment, so the models receive sanitized text with invisible-
Unicode/homoglyph tricks already stripped. The per-item verdict is aggregated across
all segments, which preserves the cross-segment rule "injection + sensitive -> BLOCK".

Cost note: this issues one Prompt Guard + one inspector call per non-empty segment, so
a multi-stream document costs several model calls. That is the intended trade for
provenance-precise findings.
"""
import re
import os
import json

from .. import db
from ..config import cfg
from . import charguard
from .backends import get_stages
from .explain import explain

# Encoding-class charguard codes for which we try to show the captured content.
_ENCODING_CODES = {"BASE64_BLOB", "HEX_BLOB", "PEM_PGP_BLOCK", "DATA_URI",
                   "HIGH_ENTROPY_REGION", "EMBEDDED_FILE_SIGNATURE", "ENCRYPTED_OR_COMPRESSED"}
_BLOB_RE = re.compile(r"(?:-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----)"
                      r"|[A-Za-z0-9+/]{40,}={0,2}|(?:[0-9A-Fa-f]{2}[\s:.\-]?){20,}")
_SNIP = 320


def _snippet(s, start=0):
    chunk = s[start:start + _SNIP]
    return chunk + ("\u2026" if len(s) - start > _SNIP else "")


def _verbatim_for(finding, text):
    """Best-effort captured content for a charguard finding (None when the content
    is invisible and showing it would be meaningless)."""
    if finding.get("samples"):
        return "; ".join(finding["samples"])
    code = finding["code"]
    if code in _ENCODING_CODES:
        pos = (finding.get("positions") or [None])[0]
        if pos is not None:
            return _snippet(text, pos)
        m = _BLOB_RE.search(text)        # escalated findings carry no position
        if m:
            return _snippet(text, m.start())
    return None


def _decision_to_tier(d):
    return {"BLOCK": "HIGH", "REVIEW": "MEDIUM", "PASS": "NONE"}[d]


def _process_segment(item_id, seg, guard, inspector):
    """Run all three gates on one segment; record findings tagged with the segment's
    provenance. Returns a small result dict used for item-level aggregation."""
    prov = seg["provenance"]
    text = seg["text"]

    # Stage 1 — charguard (deterministic; also produces sanitized text).
    report, sanitized = charguard.analyze(text.encode("utf-8"))
    cg_decision = report["decision"]
    sensitive = False
    for f in report["findings"]:
        if f["severity"] in ("MEDIUM", "HIGH"):
            sensitive = True
        title, expl = explain(f["code"])
        db.add_finding(item_id, stage="CHARGUARD", code=f["code"], severity=f["severity"],
                       title=title, explanation=f.get("detail") or expl, provenance=prov,
                       verbatim=_verbatim_for(f, text),
                       position=(f.get("positions") or [None])[0], occurrences=f.get("count"))

    # Short-circuit the expensive stages for this segment if charguard already blocks.
    if cfg.SHORT_CIRCUIT and cg_decision == "BLOCK":
        return {"cg_decision": cg_decision, "insp_decision": "PASS",
                "injection": False, "sensitive": sensitive}

    # Nothing left to inspect once sanitized to empty (e.g. a stripped invisible run).
    if not sanitized.strip():
        return {"cg_decision": cg_decision, "insp_decision": "PASS",
                "injection": False, "sensitive": sensitive}

    # Stage 2 — Prompt Guard 2 (injection shield).
    guard_res = guard.classify(sanitized)
    injection = guard_res["label"] == "malicious"
    if injection:
        title, expl = explain("INJECTION_ATTEMPT")
        db.add_finding(item_id, stage="PROMPTGUARD", code="INJECTION_ATTEMPT",
                       severity="HIGH", title=title,
                       explanation="%s (confidence %.2f over %d window(s))"
                                   % (expl, guard_res["score"], guard_res["windows"]),
                       provenance=prov, occurrences="1")

    # Stage 3 — inspector (LLM judgment), quantized verdict only.
    verdict = inspector.inspect(sanitized)
    insp_decision = verdict["decision"]
    # INJECTION_ATTEMPT is an injection signal, handled by the cross-segment
    # injection rule below — not "sensitive content". Counting it here would turn
    # the documented "injection alone -> REVIEW" into BLOCK. Only genuine content
    # categories (markings, PII, secrets, ...) mark the segment sensitive.
    if any(c.get("code") != "INJECTION_ATTEMPT" for c in verdict["categories"]):
        sensitive = True
    for c in verdict["categories"]:
        code = c["code"]
        title, expl = explain(code)
        db.add_finding(item_id, stage="INSPECTOR", code=code,
                       severity=c.get("severity", "MEDIUM"), title=title,
                       explanation=expl, provenance=prov, occurrences=c.get("occurrences", "1"))

    return {"cg_decision": cg_decision, "insp_decision": insp_decision,
            "injection": injection, "sensitive": sensitive}


def run_item(item_id):
    """Execute the full pipeline for one item. Fail-closed on any error."""
    item = db.get_item(item_id)
    if not item:
        return
    db.set_item(item_id, status="RUNNING", started_at=db.now())
    db.clear_findings(item_id)
    guard, inspector = get_stages()
    stages = {}
    try:
        # Load cached segments.
        segments, note = [], None
        if item["seg_path"]:
            with open(item["seg_path"], encoding="utf-8") as fh:
                payload = json.load(fh)
            segments = payload.get("segments", [])
            note = payload.get("note")

        # Uninspectable (unsupported format / no extractable text) -> REVIEW.
        if not segments:
            db.add_finding(item_id, stage="CHARGUARD", code="NOT_INSPECTED",
                           severity="MEDIUM", title="Could not be inspected",
                           explanation=note or "No text could be extracted from this item; "
                                               "it needs manual handling.", occurrences="1")
            _finish(item_id, "REVIEW", {"charguard": "n/a", "promptguard": "n/a",
                                        "inspector": "n/a", "note": note})
            return

        # Run every segment through all three gates.
        results = [_process_segment(item_id, seg, guard, inspector) for seg in segments]

        cg_decisions = [r["cg_decision"] for r in results]
        insp_decisions = [r["insp_decision"] for r in results]
        any_injection = any(r["injection"] for r in results)
        any_sensitive = any(r["sensitive"] for r in results)

        base = db.worst(cg_decisions + insp_decisions)
        # "Sensitive content" for the injection rule = genuine content findings:
        # inspector non-injection categories (any_sensitive) or any charguard
        # finding. It deliberately excludes the inspector's own REVIEW, which for
        # an injection-only item IS the injection signal — folding that in would
        # escalate "injection alone" to BLOCK instead of the documented REVIEW.
        sensitive = any_sensitive or db.worst(cg_decisions) != "PASS"
        if any_injection:
            decision = "BLOCK" if sensitive else "REVIEW"
        else:
            decision = base

        stages = {"charguard": db.worst(cg_decisions),
                  "promptguard": "malicious" if any_injection else "benign",
                  "inspector": db.worst(insp_decisions)}
        _finish(item_id, decision, stages)
    except Exception as e:
        db.add_finding(item_id, stage="INSPECTOR", code="PARSE_ERROR", severity="HIGH",
                       title="Inspection error",
                       explanation="The item could not be fully inspected and is blocked "
                                   "as a precaution.", occurrences="1")
        db.set_item(item_id, status="ERROR", decision="BLOCK", risk_tier="HIGH",
                    error=str(e), stages_json=json.dumps(stages), finished_at=db.now())
        _maybe_complete_job(item["job_id"])


def _finish(item_id, decision, stages):
    db.set_item(item_id, status="DONE", decision=decision,
                risk_tier=_decision_to_tier(decision),
                stages_json=json.dumps(stages), finished_at=db.now())
    item = db.get_item(item_id)
    # Drop the uploaded original now unless retention is on.
    if not cfg.RETAIN_ORIGINALS and item and item["raw_path"]:
        try:
            os.remove(item["raw_path"])
        except OSError:
            pass
    _maybe_complete_job(item["job_id"])


def _maybe_complete_job(job_id):
    items = db.list_items(job_id)
    if all(i["status"] in ("DONE", "ERROR", "SKIPPED") for i in items):
        agg = db.worst([i["decision"] for i in items])
        db.set_job(job_id, status="DONE", decision=agg, completed_at=db.now())
