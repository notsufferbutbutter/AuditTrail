"""Admin tasks, run with an admin/owner login (not the app login).

Register an application + source service and create an API key for it:
    python -m backend.admin register --app "Demo Shop" --source auth-service --env dev

The API key is printed exactly once. Only its hash is stored, so copy it now.
"""
import argparse

from backend.db import connect
from backend.repositories import ApiKeyRepository


def register(app_name: str, source_id: str, environment: str) -> str:
    with connect() as conn:
        row = conn.execute("SELECT id FROM applications WHERE name = %s", (app_name,)).fetchone()
        app_id = row[0] if row else conn.execute(
            "INSERT INTO applications (name) VALUES (%s) RETURNING id", (app_name,)).fetchone()[0]
        conn.execute(
            """INSERT INTO services (application_id, source_id, name) VALUES (%s, %s, %s)
               ON CONFLICT (application_id, source_id) DO NOTHING""",
            (app_id, source_id, source_id))
        key = ApiKeyRepository(conn).create(app_id, environment)
        conn.commit()
    print(f"application_id: {app_id}")
    print(f"API key (shown once, store it safely): {key.plaintext}")
    return key.plaintext


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    reg = sub.add_parser("register", help="register application/source and create an API key")
    reg.add_argument("--app", required=True)
    reg.add_argument("--source", required=True)
    reg.add_argument("--env", choices=["dev", "stg", "prod"], default="dev")
    args = parser.parse_args()
    register(args.app, args.source, args.env)
