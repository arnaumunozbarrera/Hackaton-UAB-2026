"""Temporary local web UI: a chat that triages an alert and shows the full prompt structure beside it.

Why: the demo must show what the AI receives and consults, not only its answer. The server only listens on
127.0.0.1, uses the standard library and serves a single static page.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..database import enrich
from ..prompt_builder import DatasetContextSource, PromptBuilder, PromptConfig
from ..triage_flow import store
from .backend import DatasetToolBackend
from .claude_code import ClaudeCodeRunner
from .client import AnthropicLLM, MockLLM, TriageRunner

STATIC = Path(__file__).parent / "static" / "chat.html"
FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
ASSET_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}
MODES = ("anthropic", "claude-code", "mock")


class App:
    """Shared state: built once. Database mode (default when the DB exists) persists every ticket."""

    def __init__(
        self, data_dir: str = "docs", mode: str = "anthropic", model: str | None = None,
        db: str | None = None, dataset: bool = False,
    ) -> None:  # fmt: skip
        if mode not in MODES:
            raise ValueError(f"modo desconocido: {mode} (usa {', '.join(MODES)})")
        self.mode, self.model = mode, model
        self.jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.flow = None
        self.claude_code = None
        db_file = enrich.db_path(db)
        if not dataset and db_file.exists():
            from ..triage_flow import TriageFlow

            self.flow = TriageFlow(db_file, data_dir, mode, model)
            self.source, self.builder, self.runner = self.flow.source, self.flow.builder, self.flow.runner
            print(f"[llm_triage] modo base de datos: {db_file}")
            return
        self.source = DatasetContextSource(data_dir)
        self.builder = PromptBuilder(self.source, PromptConfig(data_dir=Path(data_dir)))
        backend = DatasetToolBackend(self.source, self.builder)
        self.runner = TriageRunner(self.builder, backend)
        self.claude_code = ClaudeCodeRunner(self.builder, backend, model) if mode == "claude-code" else None
        _ = self.source.filter_result  # warm the log filter now (~5 s) instead of on the first triage
        if self.claude_code and ClaudeCodeRunner.ensure_subscription_auth():
            print("[llm_triage] ANTHROPIC_API_KEY retirada de este proceso: Claude Code usará tu sesión del plan")

    def alerts(self, query: str = "") -> list[dict[str, Any]]:
        """One example alert per runbook with informative logs, plus matches of the query."""
        fr, out, seen = self.source.filter_result, [], set()
        for aid, a in sorted(self.source.alerts.items()):
            q = query.strip().upper()
            hit = q and (q in aid or q in a["rule_id"])
            first = not q and a.get("runbook") not in seen and fr.kept_for_alert(aid)
            if hit or first:
                seen.add(a.get("runbook"))
                out.append({"alert_id": aid, "rule_id": a["rule_id"], "rule_name": a["rule_name"],
                            "runbook": a.get("runbook"), "informative": len(fr.kept_for_alert(aid))})  # fmt: skip
            if len(out) >= 100:
                break
        return out

    def prompt(self, alert_id: str) -> dict[str, Any]:
        package = self.builder.build(alert_id)
        return package.to_dict() | {"queries": [asdict(q) for q in package.queries]}

    def triage(self, alert_id: str, note: str = "", log: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Synchronous triage (CLI). The web UI uses start_job/job so long runs survive client timeouts."""
        if self.flow is not None:
            out = self.flow.triage(alert_id, note, log, force_llm=bool(note.strip()))
            return {"result": out["result"], "route": out["route"], "prompt": self.prompt(alert_id)}
        if self.claude_code:
            result = self.claude_code.run(alert_id, analyst_note=note, log=log)
        else:
            llm = MockLLM(self.builder.build(alert_id)) if self.mode == "mock" else AnthropicLLM(self.model)
            result = self.runner.run(alert_id, llm, note, log=log)
        print(f"[llm_triage] {alert_id}: válido={result.valid} intentos={result.attempts} "
              f"ampliaciones={sum(s['type'] == 'contexto' and not s['is_error'] for s in result.transcript)} {result.elapsed_s} s", file=sys.stderr, flush=True)  # fmt: skip
        return {"result": result.to_dict(), "prompt": self.prompt(alert_id)}

    # ------------------------------------------------------------ background jobs
    def start_job(self, alert_id: str, note: str = "") -> str:
        """Run the triage in a thread; the browser polls `job()` instead of holding one long request."""
        if alert_id not in self.source.alerts:
            raise KeyError(alert_id)
        job_id = uuid.uuid4().hex[:12]
        job: dict[str, Any] = {"status": "running", "alert_id": alert_id, "log": [], "started": time.monotonic()}
        with self._lock:
            self.jobs[job_id] = job

        def work() -> None:
            try:
                out = self.triage(alert_id, note, job["log"])
                job.update(status="done", result=out["result"], prompt=out["prompt"], route=out.get("route"))
            except Exception as exc:  # surfaced to the UI (login, network, rate limit...)
                job.update(status="error", error=f"{type(exc).__name__}: {exc}")
                print(f"[llm_triage] {alert_id}: error {job['error']}", flush=True)

        threading.Thread(target=work, daemon=True).start()
        return job_id

    def start_batch(self, limit: int) -> str:
        """Triage the `limit` most severe pending alerts in the background (database mode)."""
        if self.flow is None:
            raise RuntimeError("el lote requiere la base de datos")
        ids = self.flow.pending(limit)
        job_id = uuid.uuid4().hex[:12]
        job: dict[str, Any] = {"status": "running", "kind": "batch", "total": len(ids), "done": 0, "log": [],
                               "started": time.monotonic()}  # fmt: skip
        with self._lock:
            self.jobs[job_id] = job

        def tick(out: dict[str, Any]) -> None:
            job["done"] += 1
            job["log"].append({"alert_id": out["result"]["alert_id"], "route": out["route"],
                               "verdict": (out["result"]["ticket"] or {}).get("verdict")})  # fmt: skip

        def work() -> None:
            try:
                job.update(status="done", summary=self.flow.run_batch(alert_ids=ids, on_done=tick))
            except Exception as exc:
                job.update(status="error", error=f"{type(exc).__name__}: {exc}")

        threading.Thread(target=work, daemon=True).start()
        return job_id

    def job(self, job_id: str) -> dict[str, Any]:
        job = self.jobs[job_id]
        view = {k: v for k, v in job.items() if k not in ("started", "log")}
        return view | {"transcript": list(job["log"]), "elapsed_s": round(time.monotonic() - job["started"], 1)}


def make_handler(app: App) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, ctype: str = "application/json; charset=utf-8") -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                print(f"[llm_triage] el navegador cerró la conexión antes de recibir {self.path}", flush=True)

        def _json(self, status: int, data: Any) -> None:
            self._send(status, json.dumps(data, ensure_ascii=False, default=str).encode("utf-8"))

        def do_GET(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            qs = {k: v[0] for k, v in parse_qs(url.query).items()}
            try:
                if url.path.startswith("/api/") and self._db_get(url.path, qs):
                    return
                if url.path in ("/", "/index.html"):
                    self._send(200, (FRONTEND / "index.html").read_bytes(), ASSET_TYPES[".html"])
                elif url.path == "/chat":
                    self._send(200, STATIC.read_bytes(), "text/html; charset=utf-8")
                elif self._asset(url.path):
                    return
                elif url.path == "/api/info":
                    self._json(
                        200, {"mode": app.mode, "model": app.model or "por defecto", "database": app.flow is not None}
                    )
                elif url.path == "/api/alerts":
                    self._json(200, app.alerts(qs.get("q", "")))
                elif url.path == "/api/job":
                    self._json(200, app.job(qs["id"]))
                elif url.path == "/api/prompt":
                    self._json(200, app.prompt(qs["alert_id"]))
                else:
                    self._json(404, {"error": "not found"})
            except KeyError as exc:
                self._json(404, {"error": f"no encontrado: {exc}"})

        def _asset(self, path: str) -> bool:
            name = path.lstrip("/")
            target = (FRONTEND / name).resolve()
            if "/" in name or target.parent != FRONTEND or target.suffix not in ASSET_TYPES or not target.exists():
                return False
            self._send(200, target.read_bytes(), ASSET_TYPES[target.suffix])
            return True

        def _db_get(self, path: str, qs: dict[str, str]) -> bool:
            """Read models for the front (database mode). Returns False when the path is not one of them."""
            routes = ("/api/queue", "/api/history", "/api/stats", "/api/tickets/")
            if not path.startswith(routes):
                return False
            if app.flow is None:
                self._json(409, {"error": "requiere el modo base de datos"})
                return True
            conn, lock = app.flow.conn, app.flow.lock
            with lock:
                if path == "/api/queue":
                    self._json(200, store.queue(conn, int(qs.get("limit", 200))))
                elif path == "/api/history":
                    self._json(200, store.history(conn, int(qs.get("limit", 500))))
                elif path == "/api/stats":
                    self._json(200, store.stats(conn) | {"live": app.flow.live})
                else:
                    ticket = store.get_ticket(conn, path.rsplit("/", 1)[-1])
                    self._json(200 if ticket else 404, ticket or {"error": "sin ticket"})
            return True

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if path == "/api/decision":
                if app.flow is None:
                    self._json(409, {"error": "requiere el modo base de datos"})
                    return
                try:
                    with app.flow.lock:
                        out = store.decide(app.flow.conn, body["alert_id"], body["decision"],
                                           body.get("comment", ""), body.get("operator", ""))  # fmt: skip
                    self._json(200, out)
                except KeyError as exc:
                    self._json(404, {"error": f"no encontrado: {exc}"})
                except ValueError as exc:
                    self._json(400, {"error": str(exc)})
                return
            if path == "/api/batch":
                try:
                    self._json(202, {"job_id": app.start_batch(int(body.get("limit", 20)))})
                except RuntimeError as exc:
                    self._json(409, {"error": str(exc)})
                return
            if path != "/api/triage":
                self._json(404, {"error": "not found"})
                return
            try:
                self._json(202, {"job_id": app.start_job(body["alert_id"], body.get("note", ""))})
            except KeyError as exc:
                self._json(404, {"error": f"no encontrado: {exc}"})
            except Exception as exc:  # surfaced to the UI (API key missing, network, rate limit...)
                self._json(502, {"error": f"{type(exc).__name__}: {exc}"})

        def log_message(self, fmt: str, *args: Any) -> None:
            print(f"[llm_triage] {self.address_string()} {fmt % args}")

    return Handler


def serve(app: App, port: int = 8765) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    print(f"[llm_triage] http://127.0.0.1:{port}  (modo {app.mode})")
    server.serve_forever()
