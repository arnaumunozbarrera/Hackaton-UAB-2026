import os
import pathlib
import sqlite3

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DB = pathlib.Path(os.environ.get("TARVIA_DB", ROOT / "db" / "tarvia_soc.sqlite"))


@pytest.fixture(scope="session")
def con():
    """Read-only connection to the built database; tests marked `db` are skipped if it does not exist."""
    if not DB.exists():
        pytest.skip(f"database not built ({DB}); run scripts/rebuild")
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    c.row_factory = sqlite3.Row
    yield c
    c.close()
