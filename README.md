# AuditTrail

Angular frontend + FastAPI backend, served together as one app.

**Aufgabe 2 scope:** login, logout and one protected document endpoint
(`GET /api/documents`, returns an empty list for now). Everything else from the
building-block view is not implemented yet. See [ARCHITECTURE.md](ARCHITECTURE.md).

## How it works

1. The user clicks **Sign in with Microsoft** (Microsoft Entra ID popup).
2. The frontend sends the Microsoft access token to `POST /api/auth/login`.
3. The backend validates the token and answers with a session cookie (HttpOnly).
4. `GET /api/documents` only works with that cookie, otherwise it returns **401**.
5. **Sign out** (`POST /api/auth/logout`) deletes the session on the server, so the
   endpoint returns 401 again.

| Method | Path | Needs login | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | no | Is the app running? |
| GET | `/api/auth/config` | no | Public settings for the Microsoft login |
| POST | `/api/auth/login` | Microsoft token | Create session |
| GET | `/api/auth/session` | yes | Who is signed in? |
| POST | `/api/auth/logout` | no | End session |
| GET | `/api/documents` | **yes** | Protected document interface |

## Run locally

You need Python 3.13 and Node.js 22.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements-dev.txt
cp .env.example .env        # APP_ORIGIN=http://localhost:4200 is right for local work

set -a; source .env; set +a
uvicorn backend.main:app --reload --port 8000
```

In a second terminal:

```bash
cd frontend
npm ci
npm start
```

Open http://localhost:4200 (Angular forwards `/api` and `/health` to Python).
The Microsoft app registration must list `http://localhost:4200/` as a
**Single-page application** redirect URI.

To run the finished container instead: set `APP_ORIGIN=http://localhost:8000` in
`.env` (and register `http://localhost:8000/`), then `docker compose up --build`.

## Test

```bash
# Backend: unit + integration tests against the real HTTP API
python -m pytest -v

# Frontend: component tests
cd frontend && npm test
```

The integration tests in `backend/test/test_api.py` call the API and show that
`/api/documents` returns 401 before login, 200 after login and 401 again after
logout (also when an old cookie is reused). `test_entra.py` checks the Microsoft
token validation with locally signed test tokens.

**Manual check (also on the deployed URL):**

1. Signed out: click *Test protected endpoint* → "Access denied (401)".
2. Click *Sign in with Microsoft* and log in.
3. Click *Load documents* → "Access granted: 0 document(s)".
4. Reload the page → still signed in.
5. Click *Sign out*, then *Test protected endpoint* → denied again.

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `APP_ORIGIN` | yes | Exact public address, e.g. `https://audittrail.azurewebsites.net` (no trailing slash) |
| `ENTRA_TENANT_ID`, `ENTRA_FRONTEND_CLIENT_ID`, `ENTRA_BACKEND_CLIENT_ID` | no | Default to our app registration (public IDs, no secrets) |
| `SESSION_SECONDS` | no | Session length, default 3600 |

Microsoft Entra registration (portal → App registrations):

- Frontend registration: platform **Single-page application**, redirect URI =
  `APP_ORIGIN` + `/redirect.html`. Delegated permission `access_as_user` of the backend API.
- Backend registration: *Expose an API* with application ID URI
  `api://<backend client id>` and the scope `access_as_user`.
- No client secret is needed (the browser uses PKCE).

## Deploy and operate

Every push to `main` runs [the GitHub Actions workflow](.github/workflows/main_audittrail.yml):
frontend tests → frontend build → backend tests → deploy to the Azure App Service `audittrail`.

Azure App Service settings:

- `APP_ORIGIN` = the HTTPS address of the app
- `SCM_DO_BUILD_DURING_DEPLOYMENT=true` (installs the Python packages)
- Startup command: `python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000`
- Health check path: `/health`, and **HTTPS Only** switched on
- Keep **one instance**: sessions live in the server's memory, so a restart or a
  second instance logs users out.

Register `https://<your-app>/redirect.html` as redirect URI in Entra before the first login.
Every team member needs access to the Azure resource group and the GitHub repository
(Azure portal → *Access control (IAM)*; GitHub → *Settings → Collaborators*).
A container build is also possible with the `Dockerfile`.

## Monitoring

- **Is it running?** `curl https://<your-app>/health` must return `{"status":"OK"}`.
  Azure's health check uses the same path.
- **Logs:** Azure portal → App Service → *Monitoring → Log stream* (enable
  *Application logging* first). Locally: `docker compose logs -f api` or the uvicorn terminal.
  Every request is logged as `METHOD /path status=… duration_ms=…`; errors include a stack trace.
  Passwords and tokens are never logged.
- **Failed deployment:** open the run under the repository's *Actions* tab.
