# Group DPI binding tenant validation

Migration 165 rejects new DLP/WAF group bindings whose `org_id` differs from
their group's organization. It leaves the composite foreign key `NOT VALID` so
an upgrade does not silently remove legacy bindings. Migration 166 validates
all existing rows and **stops the upgrade** if any are still mismatched.

Before running migration 166:

1. Back up the database and run the read-only preflight using a scoped database
   account. Prefer `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, and `PGPASSWORD`
   environment variables over placing a credential URL in a process argument:

   ```sh
   psql -X -v ON_ERROR_STOP=1 -f scripts/check_group_dpi_binding_scope.sql
   ```

   A clean run prints no binding rows and exits zero. A nonzero exit prints
   binding IDs, the stored organization, the referenced group's organization,
   and sensor IDs. Do not treat a failed preflight as a safe upgrade.
2. Review every mismatch with the affected organizations. Do not change a
   binding's `org_id` to make validation pass: that would transfer security
   policy across tenants. With an authorized session in the binding's stored
   organization, delete the invalid binding through
   `DELETE /api/v1/runtime/dpi-sensor-bindings/{id}` and confirm its audit event.
   If the policy is still intended, recreate it separately in the group's own
   organization through the normal binding API. If an authorized, audited
   repair is unavailable, stop and escalate rather than deleting rows directly.
3. Rerun the preflight, apply migration 166, and verify validation:

   ```sql
   SELECT convalidated
     FROM pg_constraint
    WHERE conname = 'group_dpi_bindings_org_group_fk';
   ```

   The result must be `t`. If migration 166 fails, migration 165 still protects
   new writes; resolve the reported legacy rows and retry. No migration in this
   sequence deletes a binding.
