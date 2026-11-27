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

## Azure Log Analytics

The API sends a minimal event record to the existing Log Analytics workspace
after saving it to PostgreSQL. Azure Monitor runs the KQL rule in
`infra/repeated-login-failures.kql`; the backend also keeps its alert record for
the dashboard. If Azure ingestion fails, the API returns `503` so the source can
retry. Event IDs are deduplicated in the KQL rule.

Deploy `infra/log-analytics.bicep` to resource group `audittrail-rg`. It creates
the `AuditTrail_CL` table, a direct-ingestion data collection rule, a scheduled
query alert, and the DCR-scoped `Monitoring Metrics Publisher` role assignment.
First inspect the identity attached to the Container App:

```bash
az containerapp show \
  --resource-group audittrail-rg \
  --name audittrail-api \
  --query identity \
  --output json
```

Pass the **principal ID of the managed identity actually used by the app**. For
a user-assigned identity, find it with
`az identity show --ids <identity-resource-id> --query principalId --output tsv`.
Do not assume the GitHub deployment identity is also the app's runtime identity.

```bash
az deployment group create \
  --resource-group audittrail-rg \
  --name audittrail-log-analytics \
  --template-file infra/log-analytics.bicep \
  --parameters runtimeIdentityPrincipalId=<runtime-identity-principal-id>
```

Get the generated endpoint and immutable DCR ID:

```bash
az deployment group show \
  --resource-group audittrail-rg \
  --name audittrail-log-analytics \
  --query properties.outputs \
  --output json
```

Set those values on the Container App:

```bash
az containerapp update \
  --resource-group audittrail-rg \
  --name audittrail-api \
  --set-env-vars \
    LOG_ANALYTICS_ENDPOINT=<ingestionEndpoint> \
    LOG_ANALYTICS_DCR_ID=<dcrImmutableId> \
    LOG_ANALYTICS_STREAM_NAME=Custom-AuditTrail_CL
```

Verify that an ingested event appears in `AuditTrail_CL`, then run:

```kusto
AuditTrail_CL
| where ReceivedAt >= ago(5m)
| where Action == "user.login" and Outcome == "failure" and ActorType == "user"
| summarize by ApplicationId, Environment, ServiceId, ActorId, EventId
| summarize FailedLogins = count() by ApplicationId, Environment, ServiceId, ActorId
| where FailedLogins >= 5
```

The rule creates an Azure Monitor alert visible in the portal; no email or
webhook action group is configured.

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
