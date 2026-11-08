"""python -m src.webapp [--port 8080] [--db data/tarvia.sqlite]  (localhost only)."""

import argparse

import uvicorn

from ..llm_triage.client import load_env
from .app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", help="database (default: TARVIA_DB or data/tarvia.sqlite)")
    args = parser.parse_args()
    load_env()
    uvicorn.run(create_app(args.db), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
