"""Analyst web UI: serves `frontend/` and a small JSON API over the workflow database.

    python -m src.webapp            # http://127.0.0.1:8080 (TARVIA_DB, TARVIA_SOC_API, TARVIA_ANALYST)

Endpoints:

- GET  /api/alerts                      queue with derived status (see queries.py)
- GET  /api/alerts/{id}                 alert, events, checks, LLM transcript, ticket, decisions, actions
- GET  /api/stats                       counters for the dashboard
- GET  /api/decisions                   decision history (AI verdict vs human decision)
- POST /api/alerts/{id}/decisions       {item, decision, analyst, run_id?, override_verdict?, comment?}
- GET  /api/config                      default analyst name and API URL

Listens on localhost only; there is no authentication (local demo).
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..database.schema import ROOT
from ..soc_api import SocApi
from . import queries
from .actions import Decision, DecisionError, decide

FRONTEND = ROOT / "frontend"


class DecisionBody(BaseModel):
    item: str = Field(pattern=r"^(verdict|action:\d+)$")
    decision: str = Field(pattern=r"^(accepted|rejected)$")
    analyst: str = Field(min_length=1, max_length=80)
    run_id: int | None = None
    override_verdict: str | None = None
    comment: str = Field(default="", max_length=2000)


def get_db(request: Request) -> Iterator[sqlite3.Connection]:
    """One connection per request (WAL: reads do not block the workflow writer)."""
    # FastAPI may run the dependency and the endpoint on different threadpool threads; the connection is still
    # used by one request at a time.
    conn = sqlite3.connect(request.app.state.db_path, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


Db = Annotated[sqlite3.Connection, Depends(get_db)]


def create_app(db_path: str | Path | None = None, api: Any = None) -> FastAPI:
    """App bound to a database and a SOC API client (`api=None` -> SocApi() from TARVIA_SOC_API)."""
    path = Path(db_path or os.environ.get("TARVIA_DB") or ROOT / "data" / "tarvia.sqlite")
    if not path.exists():
        raise FileNotFoundError(f"Database not found: {path}")
    soc = api if api is not None else SocApi()
    app = FastAPI(title="Tarvia SOC - triaje N1", version="1.0")

    app.state.db_path = path

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        return {"analyst": os.environ.get("TARVIA_ANALYST", ""), "database": path.name,
                "soc_api": getattr(soc, "base_url", "replay")}  # fmt: skip

    @app.get("/api/alerts")
    def alerts(conn: Db) -> list[dict[str, Any]]:
        return queries.queue(conn)

    @app.get("/api/alerts/{alert_id}")
    def alert(alert_id: str, conn: Db) -> dict[str, Any]:
        found = queries.detail(conn, alert_id)
        if found is None:
            raise HTTPException(404, f"Alerta desconocida: {alert_id}")
        return found

    @app.get("/api/stats")
    def stats(conn: Db) -> dict[str, Any]:
        return queries.stats(conn)

    @app.get("/api/decisions")
    def decisions(conn: Db) -> list[dict[str, Any]]:
        return queries.decisions(conn)

    @app.post("/api/alerts/{alert_id}/decisions")
    def post_decision(alert_id: str, body: DecisionBody, conn: Db) -> dict[str, Any]:
        if conn.execute("SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone() is None:
            raise HTTPException(404, f"Alerta desconocida: {alert_id}")
        d = Decision(body.item, body.decision, body.analyst.strip(), body.run_id, body.override_verdict, body.comment)
        try:
            return decide(conn, soc, alert_id, d)
        except DecisionError as exc:
            raise HTTPException(exc.status, str(exc)) from exc

    @app.get("/")
    def index() -> RedirectResponse:
        return RedirectResponse("/ui/")

    if FRONTEND.exists():
        app.mount("/ui", StaticFiles(directory=FRONTEND, html=True), name="ui")
    return app
