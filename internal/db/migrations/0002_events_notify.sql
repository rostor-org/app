-- Live event fan-out (spec §9 pull-based stream, served as SSE to the
-- console). Postgres NOTIFY carries only the row id; listeners read the row,
-- so the payload is never trusted from the channel itself.
CREATE OR REPLACE FUNCTION events_notify() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('rostor_events', NEW.tenant_id || ':' || NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER events_notify_insert AFTER INSERT ON events
    FOR EACH ROW EXECUTE FUNCTION events_notify();

-- Audit appends are events too, so the console's audit view is live.
CREATE OR REPLACE FUNCTION audit_events_emit() RETURNS trigger AS $$
BEGIN
    INSERT INTO events (tenant_id, type, actor_id, target_type, target_id, payload, correlation_id)
    VALUES (NEW.tenant_id, 'audit.appended', NEW.actor_id, NEW.target_type, NEW.target_id,
            jsonb_build_object('seq', NEW.seq, 'action', NEW.action, 'outcome', NEW.outcome), NEW.correlation_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_events_emit_insert AFTER INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_emit();
