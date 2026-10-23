-- +goose Up
-- Measured on the restored 412,772-row catalog: the default page otherwise
-- scans and sorts the full wide relation. Keep descriptions out of this index.
CREATE INDEX idx_cve_catalog_default_order ON cve_records
 (kev_listed DESC, epss_probability DESC NULLS LAST, cvss_base DESC NULLS LAST,
  published_at DESC NULLS LAST, cve_id ASC);
