"""Analyst web UI (FastAPI + `frontend/`) for reviewing triage results and approving actions."""

from .app import create_app

__all__ = ["create_app"]
