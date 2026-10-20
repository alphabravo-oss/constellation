SELECT b.id AS binding_id,
       b.org_id AS binding_org_id,
       b.group_id,
       g.org_id AS group_org_id,
       b.sensor_kind,
       b.sensor_id
  FROM group_dpi_sensor_bindings b
  LEFT JOIN groups g ON g.id = b.group_id
 WHERE g.id IS NULL OR b.org_id <> g.org_id
 ORDER BY b.org_id, b.id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM group_dpi_sensor_bindings b
          LEFT JOIN groups g ON g.id = b.group_id
         WHERE g.id IS NULL OR b.org_id <> g.org_id
    ) THEN
        RAISE EXCEPTION 'legacy cross-tenant group DPI bindings require operator review before validating group_dpi_bindings_org_group_fk';
    END IF;
END;
$$;
