"""HTTP client for the simulated Tarvia SOC API (docs/06_herramientas/mock_soc_api.py)."""

import os
from collections.abc import Iterator

import requests

DEFAULT_URL = "http://127.0.0.1:8000"


class SocApi:
    def __init__(self, base_url: str | None = None, timeout: float = 120):
        self.base_url = (base_url or os.environ.get("TARVIA_SOC_API") or DEFAULT_URL).rstrip("/")
        self.session = requests.Session()
        self.timeout = timeout

    def get(self, path: str, **params: object) -> object:
        response = self.session.get(self.base_url + path, params=params, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def alerts(self, status: str = "new", page_size: int = 500) -> Iterator[dict]:
        """Yield every alert in the queue with the given status, page by page."""
        offset = 0
        while True:
            page = self.get("/alerts", status=status, limit=page_size, offset=offset)
            yield from page["items"]
            offset += len(page["items"])
            if not page["items"] or offset >= page["total"]:
                return

    def find_event(self, source: str, event_id: str) -> dict | None:
        """Return the log event with exactly this id; the API only offers substring search."""
        return self.find_log(source, "event_id", event_id)

    def find_log(self, source: str, key: str, value: str) -> dict | None:
        items = self.get(f"/logs/{source}", q=value, limit=50)["items"]
        return next((item for item in items if item.get(key) == value), None)

    def search_logs(self, source: str, q: str, limit: int = 2000) -> list[dict]:
        """Raw events of a source whose JSON contains `q` (case-insensitive substring, read-only)."""
        return self.get(f"/logs/{source}", q=q, limit=limit)["items"]

    def post(self, path: str, body: dict) -> dict:
        response = self.session.post(self.base_url + path, json=body, timeout=self.timeout)
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            raise SocApiError(response.status_code, str(detail))
        return response.json()

    def approve(self, action: str, target: str, approver: str, reason: str = "") -> dict:
        """Register a human approval (POST /approvals); returns it with its `approval_token`."""
        return self.post("/approvals", {"action": action, "target": target, "approver": approver, "reason": reason})

    def contain(
        self, action: str, target: str, justification: str, approval_token: str = "", ticket_id: str = ""
    ) -> dict:
        """Run a simulated containment action (POST /containment/{action}); 403 without a matching approval."""
        body = {"target": target, "justification": justification, "approval_token": approval_token}
        return self.post(f"/containment/{action}", body | {"ticket_id": ticket_id})


class SocApiError(RuntimeError):
    """Error answer of the SOC API (4xx/5xx) with its detail message."""

    def __init__(self, status: int, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status, self.detail = status, detail
