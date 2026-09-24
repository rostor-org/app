-- Certificate renewal and CA rotation (SPEC-cert-renewal).
-- A device keeps its previous certificate fingerprint for a grace window so
-- a renewal whose reply was lost never locks the device out; the issuing CA
-- and the trust-bundle version it last confirmed drive rotation progress.
ALTER TABLE devices
    ADD COLUMN ca_key_id         text,
    ADD COLUMN prev_fingerprint  bytea,
    ADD COLUMN prev_valid_until  timestamptz,
    ADD COLUMN trust_version     text,
    ADD COLUMN cert_renewed_at   timestamptz;
CREATE INDEX devices_prev_fingerprint_idx ON devices (prev_fingerprint) WHERE prev_fingerprint IS NOT NULL;
