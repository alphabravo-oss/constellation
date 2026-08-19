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

-- +goose Down
-- +goose StatementBegin
UPDATE role_assignments
   SET role = CASE role
       WHEN 'GlobalAdmin' THEN 'SuperAdmin'
       WHEN 'SecurityAdmin' THEN 'SecOps'
       WHEN 'ClusterAdmin' THEN 'Admin'
       WHEN 'Analyst' THEN 'Triager'
       WHEN 'Auditor' THEN 'Viewer'
       ELSE role
   END
 WHERE role IN ('GlobalAdmin', 'SecurityAdmin', 'ClusterAdmin', 'Analyst', 'Auditor');

UPDATE role_bindings
   SET role_id = CASE role_id
       WHEN 'GlobalAdmin' THEN 'platform-admin'
       WHEN 'SecurityAdmin' THEN 'security-operator'
       WHEN 'ClusterAdmin' THEN 'security-operator'
       WHEN 'Analyst' THEN 'read-only'
       WHEN 'Auditor' THEN 'compliance-auditor'
       ELSE role_id
   END
 WHERE role_id IN ('GlobalAdmin', 'SecurityAdmin', 'ClusterAdmin', 'Analyst', 'Auditor');
-- +goose StatementEnd
