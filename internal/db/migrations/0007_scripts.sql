-- SPEC-scripts: text pushed to devices, run by the agent in position order.
CREATE TABLE scripts (
    tenant_id   text NOT NULL REFERENCES tenants(id),
    id          text NOT NULL,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    language    text NOT NULL DEFAULT 'powershell' CHECK (language IN ('powershell')),
    body        text NOT NULL,
    version     integer NOT NULL DEFAULT 1,
    position    integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE script_assignments (
    tenant_id   text NOT NULL,
    id          text NOT NULL,
    script_id   text NOT NULL,
    target_kind text NOT NULL CHECK (target_kind IN ('all','group')),
    target_id   text NOT NULL,   -- resource type for 'all', group id for 'group'
    mode        text NOT NULL CHECK (mode IN ('immediate','signin')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, script_id) REFERENCES scripts(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX script_assignments_script_idx ON script_assignments (tenant_id, script_id);

-- Runs outlive their script (no FK) so history survives a delete.
CREATE TABLE script_runs (
    tenant_id    text NOT NULL,
    id           text NOT NULL,
    script_id    text NOT NULL,
    version      integer NOT NULL,
    device_id    text NOT NULL,
    principal_id text,
    mode         text NOT NULL,
    started_at   timestamptz NOT NULL,
    finished_at  timestamptz NOT NULL,
    exit_code    integer NOT NULL,
    status       text NOT NULL CHECK (status IN ('ok','failed','timeout','error')),
    output_tail  text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX script_runs_script_idx ON script_runs (tenant_id, script_id, created_at DESC);
