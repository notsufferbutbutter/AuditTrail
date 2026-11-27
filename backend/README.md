# Backend guide

## What goes where

```text
backend/
├── main.py                 # Builds the FastAPI app and connects its routers
├── config.py               # Reads and validates application settings
├── auth/
│   ├── routes.py           # Browser login, session, and logout endpoints
│   ├── dependencies.py     # Session and same-origin checks reused by routes
│   ├── entra.py            # Microsoft Entra access-token validation
│   └── sessions.py         # Creates, checks, and revokes browser sessions
├── audit/
│   ├── routes.py           # Event ingestion, event reads, and alert reads
│   ├── schemas.py          # Validated API request/response data shapes
│   ├── dependencies.py     # API-key and storage dependencies
│   ├── repository.py       # Interface the PostgreSQL adapter must implement
│   └── analysis.py         # Repeated-login-failure rule
└── test/                   # Backend API, auth, config, and analysis tests
```

`/api/documents` in `main.py` is a protected placeholder from the earlier project
stage. The AuditTrail event API is under `/v1`.

## How a dashboard login works

1. The browser requests `/api/auth/config` to get the public Entra settings.
2. The browser signs in with Entra and sends its access token to
   `POST /api/auth/login`.
3. `auth/entra.py` validates the token. `auth/sessions.py` creates a server-side
   session, returned as an HTTP-only cookie.
4. Dashboard event and alert routes use `auth/dependencies.py` to require that
   session.

## How an audit event becomes an alert

1. A source sends one event to `POST /v1/ingest` with an `X-API-Key` header.
2. `audit/dependencies.py` asks the repository to verify the key. Its registered
   application and environment—not values from the request—define the event's
   scope.
3. `audit/schemas.py` validates the submitted event. The API resolves its
   `source_id` to a registered service and sets `received_at` on the server.
4. `audit/routes.py` asks the repository to save the event. An identical retry
   is idempotent; a reused event ID with changed content returns `409`.
5. For a `user.login` failure by a user actor, `audit/analysis.py` counts
   failures for the same actor and service in the five-minute `received_at`
   window and upserts an alert when the count reaches five.
6. Authenticated dashboard clients read events and alerts with the `/v1/events`
   and `/v1/alerts` routes.

## PostgreSQL integration

`audit/repository.py` is the contract for the PostgreSQL adapter. The adapter
must implement `AuditRepository` and be assigned to
`app.state.audit_repository` when the app starts. Until that is wired, audit
routes return `503 Audit storage is unavailable`; they do not silently keep data
in memory.

## Run backend tests

```bash
python -m pytest -q backend/test
```
