-- Rostor initial schema. Every table carries tenant_id from the first
-- migration (spec D4): multi-tenant is a flag flip, never a schema migration.
-- IDs are opaque prefixed strings minted by the application (never reused).

CREATE TABLE tenants (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- §2.1 Principal. kind: user | service | device. display_name is a
-- {locale: string} map with "en" fallback (spec D7).
CREATE TABLE principals (
    tenant_id    text NOT NULL REFERENCES tenants(id),
    id           text NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('user','service','device')),
    username     text,
    display_name jsonb NOT NULL DEFAULT '{}'::jsonb,
    state        text NOT NULL CHECK (state IN ('applicant','invited','active','suspended','deprovisioned','archived')),
    attributes   jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX principals_username_uq ON principals (tenant_id, lower(username)) WHERE username IS NOT NULL;

-- §2.2 Group. One primitive. Static membership only in this slice; the
-- rule column exists so dynamic groups are additive later.
CREATE TABLE groups (
    tenant_id    text NOT NULL REFERENCES tenants(id),
    id           text NOT NULL,
    name         text NOT NULL,
    display_name jsonb NOT NULL DEFAULT '{}'::jsonb,
    kind         text NOT NULL DEFAULT 'static' CHECK (kind IN ('static','dynamic')),
    rule         text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE group_members (
    tenant_id   text NOT NULL,
    group_id    text NOT NULL,
    member_kind text NOT NULL CHECK (member_kind IN ('principal','group')),
    member_id   text NOT NULL,
    added_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, group_id, member_kind, member_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX group_members_member_idx ON group_members (tenant_id, member_kind, member_id);

-- §2.3 Resource. Optional parent for scoping; a grant on a parent applies
-- to its descendants.
CREATE TABLE resources (
    tenant_id   text NOT NULL REFERENCES tenants(id),
    type        text NOT NULL,
    id          text NOT NULL,
    parent_type text,
    parent_id   text,
    attributes  jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, type, id)
);

-- §2.4 Role: a named bundle of permissions on a resource type.
CREATE TABLE roles (
    tenant_id     text NOT NULL REFERENCES tenants(id),
    resource_type text NOT NULL,
    name          text NOT NULL,
    permissions   text[] NOT NULL,
    PRIMARY KEY (tenant_id, resource_type, name)
);

-- §3.1 Grants: (principal|group, role, resource) + optional CEL condition.
-- condition_class is fixed at write time (offline | online) per §3.1.
CREATE TABLE grants (
    tenant_id       text NOT NULL REFERENCES tenants(id),
    id              text NOT NULL,
    subject_kind    text NOT NULL CHECK (subject_kind IN ('principal','group')),
    subject_id      text NOT NULL,
    role            text NOT NULL,
    resource_type   text NOT NULL,
    resource_id     text NOT NULL,
    condition       text,
    condition_class text NOT NULL DEFAULT 'offline' CHECK (condition_class IN ('offline','online')),
    not_before      timestamptz,
    expires_at      timestamptz,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX grants_subject_idx ON grants (tenant_id, subject_kind, subject_id) WHERE revoked_at IS NULL;
CREATE INDEX grants_resource_idx ON grants (tenant_id, resource_type, resource_id) WHERE revoked_at IS NULL;

-- §2.5 / §4 Policy. A tenant-wide value is an assignment with group_id NULL
-- at low priority; there is no separate settings system.
CREATE TABLE policies (
    tenant_id  text NOT NULL REFERENCES tenants(id),
    id         text NOT NULL,
    name       text NOT NULL,
    domain     text NOT NULL,
    priority   integer NOT NULL,
    document   jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE policy_assignments (
    tenant_id  text NOT NULL,
    policy_id  text NOT NULL,
    group_id   text,
    PRIMARY KEY (tenant_id, policy_id, group_id),
    FOREIGN KEY (tenant_id, policy_id) REFERENCES policies(tenant_id, id) ON DELETE CASCADE
);

-- §7.2 Authenticator bindings. Material lives in the sealed store below,
-- as opaque bytes keyed by binding; methods verify through the contract.
CREATE TABLE authenticator_bindings (
    tenant_id    text NOT NULL REFERENCES tenants(id),
    id           text NOT NULL,
    principal_id text NOT NULL,
    method       text NOT NULL,
    properties   text[] NOT NULL,
    label        text,
    state        text NOT NULL DEFAULT 'active' CHECK (state IN ('active','revoked')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES principals(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX bindings_principal_idx ON authenticator_bindings (tenant_id, principal_id, method) WHERE state = 'active';

CREATE TABLE credential_material (
    tenant_id  text NOT NULL,
    binding_id text NOT NULL,
    sealed     bytea NOT NULL,
    PRIMARY KEY (tenant_id, binding_id),
    FOREIGN KEY (tenant_id, binding_id) REFERENCES authenticator_bindings(tenant_id, id) ON DELETE CASCADE
);

-- §7.6 Cross-method lockout is core state, never per-method.
CREATE TABLE auth_failures (
    tenant_id    text NOT NULL,
    principal_id text NOT NULL,
    failed_count integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, principal_id)
);

-- §7.6 Ceremonies are asynchronous and resumable; every authentication,
-- even a single-step inline one, is a persisted ceremony.
CREATE TABLE ceremonies (
    tenant_id    text NOT NULL REFERENCES tenants(id),
    id           text NOT NULL,
    method       text NOT NULL,
    mode         text NOT NULL CHECK (mode IN ('inline','redirect','out_of_band','headless')),
    principal_id text,
    state        text NOT NULL CHECK (state IN ('pending','completed','failed','expired')),
    data         jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE sessions (
    tenant_id    text NOT NULL REFERENCES tenants(id),
    id           text NOT NULL,
    principal_id text NOT NULL,
    token_hash   bytea NOT NULL,
    assurance    text NOT NULL,
    properties   text[] NOT NULL,
    device_id    text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX sessions_token_idx ON sessions (token_hash);

-- Long-lived API tokens for service accounts (admin CLI). Creating one is
-- the §7.5 "explicit exception" and is audited as such.
CREATE TABLE api_tokens (
    tenant_id    text NOT NULL REFERENCES tenants(id),
    id           text NOT NULL,
    principal_id text NOT NULL,
    token_hash   bytea NOT NULL,
    label        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    revoked_at   timestamptz,
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX api_tokens_hash_idx ON api_tokens (token_hash);

-- §5 Devices are principals with extra machinery.
CREATE TABLE devices (
    tenant_id        text NOT NULL,
    principal_id     text NOT NULL,
    lifecycle        text NOT NULL CHECK (lifecycle IN ('enrolled','trusted','quarantined','retired')),
    cert_serial      text NOT NULL,
    cert_fingerprint bytea NOT NULL,
    cert_not_after   timestamptz NOT NULL,
    posture          jsonb NOT NULL DEFAULT '{}'::jsonb,
    enrolled_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz,
    PRIMARY KEY (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES principals(tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX devices_fingerprint_idx ON devices (cert_fingerprint);

CREATE TABLE enrollment_tokens (
    tenant_id     text NOT NULL REFERENCES tenants(id),
    id            text NOT NULL,
    token_hash    bytea NOT NULL,
    resource_type text NOT NULL,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    used_by       text,
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX enrollment_tokens_hash_idx ON enrollment_tokens (token_hash);

-- D3: the core is the CA. Private keys are sealed by the crypto provider.
CREATE TABLE ca_keys (
    tenant_id   text NOT NULL REFERENCES tenants(id),
    id          text NOT NULL,
    purpose     text NOT NULL CHECK (purpose IN ('ca','signing')),
    algorithm   text NOT NULL,
    public_pem  text NOT NULL,
    cert_pem    text,
    key_sealed  bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz,
    PRIMARY KEY (tenant_id, id)
);

-- §14 Tamper-evident audit log: append-only, hash-chained per tenant.
CREATE TABLE audit_heads (
    tenant_id text PRIMARY KEY,
    seq       bigint NOT NULL,
    hash      bytea NOT NULL
);
CREATE TABLE audit_events (
    tenant_id       text NOT NULL,
    seq             bigint NOT NULL,
    ts              timestamptz NOT NULL DEFAULT now(),
    actor_kind      text NOT NULL,
    actor_id        text NOT NULL,
    action          text NOT NULL,
    target_type     text,
    target_id       text,
    credential_type text,
    assurance       text,
    outcome         text NOT NULL,
    -- json (not jsonb) so the stored bytes are exactly what was hashed.
    detail          json NOT NULL,
    correlation_id  text NOT NULL,
    prev_hash       bytea NOT NULL,
    hash            bytea NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);
-- Append-only is enforced at the database, not by convention.
CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

-- §9 typed event stream (pull-based in this slice).
CREATE TABLE events (
    tenant_id      text NOT NULL,
    id             bigserial,
    ts             timestamptz NOT NULL DEFAULT now(),
    type           text NOT NULL,
    actor_id       text,
    target_type    text,
    target_id      text,
    payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
    correlation_id text NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
