"""Single background worker.

The inspector is one CPU-bound model that cannot parallelise usefully, so we use
one worker thread that owns the model and drains a FIFO queue, rather than a pool
that would load N copies of a multi-GB model. The web layer never blocks on
inspection — it enqueues and reads status from SQLite.
"""
import threading
import queue
import logging

from . import db
from .pipeline.orchestrator import run_item

log = logging.getLogger("worker")

_q = "queue.Queue[str]"
_jobs_q: "queue.Queue" = queue.Queue()
_thread = None
_started = False


def enqueue(item_id):
    db.set_item(item_id, status="QUEUED")
    _jobs_q.put(item_id)


def _loop():
    # Warm the model stack once (no-op for the mock backend).
    try:
        from .pipeline.backends import get_stages
        get_stages()
    except Exception:
        log.exception("model stack failed to load; items will fail closed")
    while True:
        item_id = _jobs_q.get()
        if item_id is None:
            return
        try:
            run_item(item_id)
        except Exception:
            log.exception("worker error on item %s", item_id)
        finally:
            _jobs_q.task_done()


def start():
    global _thread, _started
    if _started:
        return
    _started = True
    # Crash recovery: re-enqueue anything left mid-flight.
    for iid in db.queued_item_ids():
        _jobs_q.put(iid)
    _thread = threading.Thread(target=_loop, name="inspect-worker", daemon=True)
    _thread.start()
    log.info("inspection worker started")
