-- A tenant-wide assignment has group_id NULL, which a primary key cannot
-- hold. Replace the key with a uniqueness rule that treats NULL as the
-- tenant-wide slot.
ALTER TABLE policy_assignments DROP CONSTRAINT policy_assignments_pkey;
CREATE UNIQUE INDEX policy_assignments_uq ON policy_assignments (tenant_id, policy_id, coalesce(group_id, ''));
ALTER TABLE policy_assignments ALTER COLUMN group_id DROP NOT NULL;
