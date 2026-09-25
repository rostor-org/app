-- SPEC-agents: a fourth principal kind. An agent is owned by a person
-- (attributes.owner_id) and can never do more than its owner (authz).
ALTER TABLE principals DROP CONSTRAINT principals_kind_check;
ALTER TABLE principals ADD CONSTRAINT principals_kind_check CHECK (kind IN ('user','service','device','agent'));
