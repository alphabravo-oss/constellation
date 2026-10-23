-- +goose Up
-- Reference checks must remain bounded as scan histories grow.
CREATE INDEX idx_scan_attestations_job_reference ON scan_result_attestations(scan_job_id)
 WHERE scan_job_id IS NOT NULL;
CREATE INDEX idx_image_results_job_reference ON image_scan_results(last_scan_job_id)
 WHERE last_scan_job_id IS NOT NULL;
CREATE INDEX idx_scan_jobs_terminal_expiry ON scan_jobs(finished_at,id)
 WHERE status IN ('completed','failed','canceled');
CREATE INDEX idx_scan_jobs_terminal_latest ON scan_jobs(org_id,target_id,finished_at DESC,id DESC)
 WHERE finished_at IS NOT NULL;
