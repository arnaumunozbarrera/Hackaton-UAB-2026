"""Background service used by the web server: one worker reconstructs attack chains one at a time.

Why: a reconstruction can take minutes with a real model and is triggered from several places (an escalated
ticket after triage, the operator's Escalate decision, the button in the investigation view). A single queue keeps
cost and database load bounded, avoids two runs for the same alert, and lets the browser poll the progress.
"""

from __future__ import annotations

import queue
import sqlite3
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from . import store
from .catalogue import InvestigationBackend
from .runner import ChainRunner

MODES = ("mock", "anthropic", "claude-code")


def escalated(ticket: dict[str, Any] | None) -> bool:
    return bool(((ticket or {}).get("escalation") or {}).get("escalate"))


class ChainService:
    def __init__(self, db_path: str | Path, conn: sqlite3.Connection, lock: Any, data_dir: str | Path = "docs",
                 mode: str = "mock", model: str | None = None) -> None:  # fmt: skip
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode}")
        self.conn, self.lock, self.mode, self.model = conn, lock, mode, model
        with self.lock:
            store.ensure(conn)
        self.runner = ChainRunner(InvestigationBackend(db_path), data_dir)
        self.jobs: dict[str, dict[str, Any]] = {}
        self.by_alert: dict[str, str] = {}
        self._queue: queue.Queue[str] = queue.Queue()
        self._jobs_lock = threading.Lock()
        threading.Thread(target=self._worker, daemon=True, name="attack-chain").start()

    def start(self, alert_id: str, trigger: str = "manual", mode: str | None = None) -> str:
        """Queue a reconstruction (returns the running or queued job of the alert if there is one)."""
        mode = mode if mode in MODES else self.mode
        with self._jobs_lock:
            current = self.by_alert.get(alert_id)
            if current and self.jobs[current]["status"] in ("queued", "running"):
                return current
            job_id = uuid.uuid4().hex[:12]
            self.jobs[job_id] = {"status": "queued", "kind": "chain", "alert_id": alert_id, "trigger": trigger,
                                 "mode": mode, "log": [], "started": time.monotonic()}  # fmt: skip
            self.by_alert[alert_id] = job_id
        self._queue.put(job_id)
        return job_id

    def maybe_start(self, alert_id: str, ticket: dict[str, Any] | None, trigger: str) -> str | None:
        """Automatic trigger: only escalated tickets, and only once per alert (a stored report is kept)."""
        if not escalated(ticket):
            return None
        with self.lock:
            if store.get(self.conn, alert_id) is not None:
                return None
        return self.start(alert_id, trigger)

    def _worker(self) -> None:
        while True:
            job_id = self._queue.get()
            job = self.jobs[job_id]
            job.update(status="running", started=time.monotonic())
            try:
                result = self.runner.run(job["alert_id"], mode=job["mode"], model=self.model, log=job["log"]).to_dict()
                with self.lock:
                    store.save(self.conn, result, job["trigger"])
                job.update(status="done", valid=result["valid"], errors=result["errors"])
                print(f"[chain] {job['alert_id']}: valid={result['valid']} attempts={result['attempts']} "
                      f"{result['elapsed_s']} s", file=sys.stderr, flush=True)  # fmt: skip
            except Exception as exc:  # surfaced to the UI (no ticket, login, network...)
                job.update(status="error", error=f"{type(exc).__name__}: {exc}")
                print(f"[chain] {job['alert_id']}: error {job['error']}", file=sys.stderr, flush=True)

    def job(self, job_id: str) -> dict[str, Any]:
        job = self.jobs[job_id]
        view = {k: v for k, v in job.items() if k not in ("started", "log")}
        return view | {"transcript": list(job["log"]), "elapsed_s": round(time.monotonic() - job["started"], 1)}

    def get(self, alert_id: str) -> dict[str, Any]:
        """Stored report (if any) plus the running or queued job of the alert (if any)."""
        with self.lock:
            report = store.get(self.conn, alert_id)
        job_id = self.by_alert.get(alert_id)
        job = self.job(job_id) if job_id else None
        return {"alert_id": alert_id, "chain": report, "job_id": job_id if job else None, "job": job}
