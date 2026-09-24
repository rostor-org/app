-- Credentials that identify the person by themselves (spec §7.2
-- "can-identify-user"): a badge by any of its observed forms, a passkey by
-- its credential ID. The core resolves a presented identifier to a binding
-- here, then hands verification to the method. Values are canonicalised by
-- the method (lower-case hex, decimal without leading zeros, base64url).
CREATE TABLE credential_identifiers (
    tenant_id  text NOT NULL,
    binding_id text NOT NULL,
    kind       text NOT NULL,   -- badge.uid | badge.wiegand26 | badge.printed | webauthn.id
    value      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, kind, value),
    FOREIGN KEY (tenant_id, binding_id) REFERENCES authenticator_bindings(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX credential_identifiers_binding_idx ON credential_identifiers (tenant_id, binding_id);
