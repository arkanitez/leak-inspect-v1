"""Tests for the evidence view (located spans), the masked-span reveal endpoint,
and the jobs list. Runs against the mock backend."""
import os, time, tempfile, pathlib

os.environ["MODEL_BACKEND"] = "mock"
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="wl-ev-")

from fastapi.testclient import TestClient
from app.main import app

SAMPLE = pathlib.Path("/mnt/user-data/outputs/sample-docs/leak.docx")

# Crafted so the MOCK inspector flags it AND the locator can pin every span:
#   password=...  -> SECRET_CREDENTIAL (masked)
#   S7712345A     -> PII               (masked)
#   SECRET//NOFORN-> CLASS_MARKING + DISSEM_CAVEAT (highlighted)
CRAFTED = ("DB host config: password=Sup3rSecret! for the migration. "
           "Candidate NRIC S7712345A is on file. "
           "Header still reads SECRET//NOFORN from the source draft.")


def poll_done(c, jid, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        s = c.get("/api/jobs/%s/status" % jid).json()
        if s["status"] in ("DONE", "ERROR"):
            return s
        time.sleep(0.2)
    raise AssertionError("job did not finish in time")


def run():
    with TestClient(app) as c:
        files = []
        if SAMPLE.exists():
            files = [("files", ("leak.docx", SAMPLE.read_bytes(), "application/octet-stream"))]
        else:
            print("NOTE: leak.docx sample not found; running text-only.")

        r = c.post("/api/jobs", data={"name": "evidence-test", "texts": [CRAFTED]}, files=files)
        assert r.status_code == 200, (r.status_code, r.text)
        jid = r.json()["id"]

        # ---- jobs list: appears as in-progress before confirm? (it's DRAFT -> excluded) ----
        lst = c.get("/api/jobs").json()
        ids_all = {j["id"] for j in lst["in_progress"]} | {j["id"] for j in lst["completed"]}
        assert jid not in ids_all, "unconfirmed DRAFT should not appear in the jobs list"

        c.post("/api/jobs/%s/confirm" % jid)
        poll_done(c, jid)

        # ---- jobs list: now in completed, with a label and verdict ----
        lst = c.get("/api/jobs").json()
        entry = next((j for j in lst["completed"] if j["id"] == jid), None)
        assert entry, "confirmed+finished job must show under completed"
        assert entry["label"] == "evidence-test"
        assert entry["decision"] in ("PASS", "REVIEW", "BLOCK")
        assert entry["done"] == entry["item_count"]
        print("jobs list OK: completed=%d label=%r verdict=%s"
              % (len(lst["completed"]), entry["label"], entry["decision"]))

        # ---- find the crafted text item ----
        items = c.get("/api/jobs/%s/status" % jid).json()["items"]
        txt = next(it for it in items if it["source_name"].startswith("text-chunk"))
        d = c.get("/api/jobs/%s/items/%s" % (jid, txt["id"])).json()

        # segments present; collect parts on the "Text" segment
        segs = {s["provenance"]: s["parts"] for s in d["segments"]}
        assert "Text" in segs, "expected a Text segment in evidence"
        parts = segs["Text"]
        kinds = [p["kind"] for p in parts]
        assert "mask" in kinds, "expected masked secret/PII spans"
        assert "hl" in kinds, "expected highlighted marking spans"

        # masked parts carry an index but NEVER the cleartext
        masks = [p for p in parts if p["kind"] == "mask"]
        assert all("t" not in p or p["t"] is None for p in masks), "mask parts must not carry cleartext"
        mids = sorted(p["mid"] for p in masks)
        assert mids == list(range(len(masks))), "mask indices must be 0..n-1"

        # highlighted parts DO carry their (non-secret) text
        hls = [p["t"] for p in parts if p["kind"] == "hl"]
        assert any("SECRET" in t or "NOFORN" in t for t in hls), hls
        print("evidence OK: %d parts (%d masked, %d highlighted) on Text segment"
              % (len(parts), len(masks), len(hls)))

        # ---- reveal endpoint: returns the right cleartext for each masked span ----
        revealed = []
        for mid in mids:
            rv = c.get("/api/jobs/%s/items/%s/reveal" % (jid, txt["id"]),
                       params={"prov": "Text", "mid": mid})
            assert rv.status_code == 200, (rv.status_code, rv.text)
            revealed.append(rv.json()["value"])
        assert "Sup3rSecret!" in revealed, revealed
        assert "S7712345A" in revealed, revealed
        print("reveal OK: %r" % revealed)

        # ---- reveal: out-of-range and unknown provenance both 404 ----
        assert c.get("/api/jobs/%s/items/%s/reveal" % (jid, txt["id"]),
                     params={"prov": "Text", "mid": 99}).status_code == 404
        assert c.get("/api/jobs/%s/items/%s/reveal" % (jid, txt["id"]),
                     params={"prov": "Nonexistent", "mid": 0}).status_code == 404
        print("reveal 404s OK")

        # ---- UI routes render ----
        assert c.get("/jobs").status_code == 200
        assert c.get("/jobs/%s/items/%s" % (jid, txt["id"])).status_code == 200
        assert c.get("/jobs/%s/results" % jid).status_code == 200
        print("UI routes OK (/jobs, item, results)")

        # ---- leak.docx (if present): endpoint returns 200 with segments across streams ----
        if SAMPLE.exists():
            doc = next(it for it in items if it["source_name"] == "leak.docx")
            dd = c.get("/api/jobs/%s/items/%s" % (jid, doc["id"])).json()
            provs = {s["provenance"] for s in dd["segments"]}
            print("leak.docx evidence segments: %s" % sorted(provs))

    print("\nALL EVIDENCE/JOBS ASSERTIONS PASSED")


if __name__ == "__main__":
    run()
