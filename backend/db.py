"""Database connections.

Two ways to log in, both configured only through environment variables:

* Local development: DATABASE_URL=postgresql://user:password@localhost:5432/audittrail
  (lives in your untracked .env, never in Git).
* Azure: DB_AUTH=managed-identity plus PGHOST, PGDATABASE, PGUSER. The Container App's
  managed identity gets a short-lived Entra token that is used as the password,
  so there is no database password anywhere.

Every connection that is not to localhost must use TLS (sslmode=verify-full or require).
"""
import os

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo

ENTRA_DB_SCOPE = "https://ossrdbms-aad.database.windows.net/.default"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "db", ""}
SAFE_SSLMODES = {"require", "verify-ca", "verify-full"}


_credential = None


def _entra_token() -> str:
    """Short-lived token for the managed identity; the credential caches and renews it."""
    global _credential
    if _credential is None:
        from azure.identity import ManagedIdentityCredential  # only needed in Azure
        client_id = os.getenv("AZURE_CLIENT_ID")  # set for a user-assigned identity
        _credential = ManagedIdentityCredential(client_id=client_id) if client_id else ManagedIdentityCredential()
    return _credential.get_token(ENTRA_DB_SCOPE).token


def is_configured(env=os.environ) -> bool:
    return env.get("DB_AUTH") == "managed-identity" or "DATABASE_URL" in env


def conninfo(env=os.environ) -> str:
    if env.get("DB_AUTH") == "managed-identity":
        params = {
            "host": env["PGHOST"],
            "dbname": env.get("PGDATABASE", "audittrail"),
            "user": env["PGUSER"],
            "password": _entra_token(),
            "sslmode": env.get("PGSSLMODE", "require"),
        }
    elif "DATABASE_URL" in env:
        params = conninfo_to_dict(env["DATABASE_URL"])
    else:
        raise ValueError("Set DATABASE_URL (local) or DB_AUTH=managed-identity with PGHOST/PGUSER (Azure)")

    host = str(params.get("host", ""))
    if host not in LOCAL_HOSTS and params.get("sslmode") not in SAFE_SSLMODES:
        raise ValueError("Remote database connections must use sslmode=require or stricter")
    params.setdefault("application_name", "audittrail")
    params.setdefault("connect_timeout", 10)
    return make_conninfo(**params)


def connect(env=os.environ) -> psycopg.Connection:
    return psycopg.connect(conninfo(env))
