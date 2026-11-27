"""Apply versioned SQL migrations in backend/migrations in name order, each exactly once.

Run with an admin/owner login, not with the app login:
    DATABASE_URL=... python -m backend.migrate
"""
import logging
from pathlib import Path

import psycopg

from backend.db import connect

MIGRATIONS = Path(__file__).resolve().parent / "migrations"
LOCK_ID = 4711_2026  # advisory lock so two deployments never migrate at the same time
logger = logging.getLogger(__name__)


def migrate(conn: psycopg.Connection, directory: Path = MIGRATIONS) -> list[str]:
    applied_now = []
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (LOCK_ID,))
        conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                            version    TEXT PRIMARY KEY,
                            applied_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
        done = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
        for file in sorted(directory.glob("*.sql")):
            if file.name in done:
                continue
            logger.info("Applying %s", file.name)
            conn.execute(file.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (file.name,))
            applied_now.append(file.name)
    return applied_now


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    with connect() as connection:
        print("Applied:", migrate(connection) or "nothing, already up to date")
