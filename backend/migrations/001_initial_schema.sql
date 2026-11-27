-- 001: initial AuditTrail schema.
-- Run by the schema owner (migration/admin login), never by the running app.
-- The app logs in with its own login that is a member of the NOLOGIN role
-- audittrail_app, which only gets the rights listed at the bottom.

CREATE TABLE applications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(100) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE services (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications (id),
    source_id      VARCHAR(100) NOT NULL,
    name           VARCHAR(100) NOT NULL,
    description    TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (application_id, source_id),
    UNIQUE (application_id, id)  -- target of the composite FK from audit_events/alerts
);

CREATE TABLE api_keys (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications (id),
    environment    VARCHAR(10) NOT NULL CHECK (environment IN ('dev', 'stg', 'prod')),
    key_id         VARCHAR(50) NOT NULL UNIQUE,          -- public part, e.g. at_3f9c...
    key_hash       CHAR(64) NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),  -- SHA-256 hex, never the key
    status         VARCHAR(10) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    expires_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ,
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE TABLE audit_events (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id       VARCHAR(100) NOT NULL,
    application_id UUID NOT NULL REFERENCES applications (id),
    environment    VARCHAR(10) NOT NULL CHECK (environment IN ('dev', 'stg', 'prod')),
    service_id     UUID NOT NULL,
    action         VARCHAR(200) NOT NULL,
    outcome        VARCHAR(10) NOT NULL CHECK (outcome IN ('success', 'failure')),
    actor          JSONB NOT NULL CHECK (jsonb_typeof(actor) = 'object'),
    targets        JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(targets) = 'array'),
    occurred_at    TIMESTAMPTZ NOT NULL,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata       JSONB,
    UNIQUE (application_id, environment, event_id),
    FOREIGN KEY (application_id, service_id) REFERENCES services (application_id, id)
);

CREATE INDEX audit_events_list_idx
    ON audit_events (application_id, environment, received_at DESC);
-- Supports the 5-minute analysis of failed logins per service and actor.
CREATE INDEX audit_events_failed_login_idx
    ON audit_events (service_id, (actor ->> 'id'), received_at)
    WHERE outcome = 'failure';

CREATE TABLE alerts (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications (id),
    environment    VARCHAR(10) NOT NULL CHECK (environment IN ('dev', 'stg', 'prod')),
    service_id     UUID NOT NULL,
    rule_code      VARCHAR(50) NOT NULL,
    actor_id       VARCHAR(200) NOT NULL,
    severity       VARCHAR(10) NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    status         VARCHAR(15) NOT NULL DEFAULT 'open'
                   CHECK (status IN ('open', 'acknowledged', 'resolved')),
    title          VARCHAR(200) NOT NULL,
    description    TEXT,
    failure_count  INTEGER NOT NULL CHECK (failure_count > 0),
    window_start   TIMESTAMPTZ NOT NULL,
    window_end     TIMESTAMPTZ NOT NULL CHECK (window_end >= window_start),
    first_seen_at  TIMESTAMPTZ NOT NULL,
    last_seen_at   TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (application_id, service_id) REFERENCES services (application_id, id)
);

-- At most one unresolved alert per app/env/service/rule/actor, so analyzer retries update it.
CREATE UNIQUE INDEX alerts_one_active_idx
    ON alerts (application_id, environment, service_id, rule_code, actor_id)
    WHERE status <> 'resolved';
CREATE INDEX alerts_list_idx ON alerts (application_id, environment, created_at DESC);

-- Where the scheduled analysis worker stopped (one row per rule).
CREATE TABLE analysis_state (
    rule_code       VARCHAR(50) PRIMARY KEY,
    last_checked_at TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only, layer 1: a trigger rejects UPDATE/DELETE/TRUNCATE on audit events,
-- whoever runs them. (The table owner could still disable the trigger, see README.)
CREATE FUNCTION reject_audit_event_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (% rejected)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_audit_event_change();
CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_event_change();

-- Append-only, layer 2: least-privilege role for the running app.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audittrail_app') THEN
        CREATE ROLE audittrail_app NOLOGIN;
    END IF;
END;
$$;

REVOKE ALL ON applications, services, api_keys, audit_events, alerts, analysis_state FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO audittrail_app;
GRANT SELECT ON applications, services TO audittrail_app;
GRANT SELECT, INSERT, UPDATE (status, revoked_at) ON api_keys TO audittrail_app;
GRANT SELECT, INSERT ON audit_events TO audittrail_app;          -- no UPDATE, no DELETE
GRANT SELECT, INSERT, UPDATE ON alerts TO audittrail_app;
GRANT SELECT, INSERT, UPDATE ON analysis_state TO audittrail_app;
