-- +goose Up
-- +goose StatementBegin
-- Record the actual rendered artifact, independent of mutable schedule settings.
-- Legacy history remains explicitly unknown; no format/filename backfill.
ALTER TABLE compliance_runs ADD COLUMN artifact_format text,
    ADD COLUMN artifact_media_type text,
    ADD COLUMN artifact_filename text;
ALTER TABLE compliance_runs ADD CONSTRAINT compliance_run_artifact_metadata CHECK (
 (artifact_format IS NULL AND artifact_media_type IS NULL AND artifact_filename IS NULL)
 OR (artifact_format IS NOT NULL AND artifact_media_type IS NOT NULL AND artifact_format IN ('html','json','csv','sarif','pdf')
     AND artifact_media_type = CASE artifact_format WHEN 'html' THEN 'text/html; charset=utf-8' WHEN 'json' THEN 'application/json' WHEN 'csv' THEN 'text/csv; charset=utf-8' WHEN 'sarif' THEN 'application/sarif+json' WHEN 'pdf' THEN 'application/pdf' END
     AND artifact_filename IS NOT NULL AND artifact_filename <> ''
     AND artifact_filename NOT IN ('.','..') AND artifact_filename !~ E'[/\\\\]')
);
CREATE FUNCTION compliance_artifact_metadata_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.artifact_format IS NOT NULL AND
       ROW(NEW.artifact_format,NEW.artifact_media_type,NEW.artifact_filename,NEW.artifact_uri)
       IS DISTINCT FROM ROW(OLD.artifact_format,OLD.artifact_media_type,OLD.artifact_filename,OLD.artifact_uri) THEN
        RAISE EXCEPTION 'recorded compliance artifact identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER compliance_artifact_metadata_immutable BEFORE UPDATE ON compliance_runs
    FOR EACH ROW EXECUTE FUNCTION compliance_artifact_metadata_immutable();
-- +goose StatementEnd
