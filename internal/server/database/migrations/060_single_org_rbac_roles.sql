-- Normalize the greenfield single-org RBAC model to product-facing role names.

-- +goose Up
-- +goose StatementBegin
UPDATE role_assignments
   SET role = CASE role
       WHEN 'SuperAdmin' THEN 'GlobalAdmin'
       WHEN 'Admin' THEN 'GlobalAdmin'
       WHEN 'SecOps' THEN 'SecurityAdmin'
       WHEN 'Triager' THEN 'Analyst'
       WHEN 'Viewer' THEN 'Auditor'
       ELSE role
   END
 WHERE role IN ('SuperAdmin', 'Admin', 'SecOps', 'Triager', 'Viewer');

UPDATE role_bindings
   SET role_id = CASE role_id
       WHEN 'platform-admin' THEN 'GlobalAdmin'
       WHEN 'security-operator' THEN 'SecurityAdmin'
       WHEN 'compliance-auditor' THEN 'Auditor'
       WHEN 'read-only' THEN 'Auditor'
       WHEN 'SuperAdmin' THEN 'GlobalAdmin'
       WHEN 'Admin' THEN 'GlobalAdmin'
       WHEN 'SecOps' THEN 'SecurityAdmin'
       WHEN 'Triager' THEN 'Analyst'
       WHEN 'Viewer' THEN 'Auditor'
       ELSE role_id
   END
 WHERE role_id IN (
       'platform-admin',
       'security-operator',
       'compliance-auditor',
       'read-only',
       'SuperAdmin',
       'Admin',
       'SecOps',
       'Triager',
       'Viewer'
   );
-- +goose StatementEnd
