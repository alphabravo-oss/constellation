-- +goose Up
-- +goose StatementBegin
-- Profile, organization, disable state, last login and grants remain in users and
-- role_assignments. Local credentials extend that identity rather than copying it.
CREATE UNIQUE INDEX users_org_email_casefold ON users(org_id,lower(email));
CREATE TABLE local_users (
 user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 password_hash text NOT NULL,
 totp_secret bytea NOT NULL,
 key_id text NOT NULL,
 algorithm text NOT NULL CHECK(algorithm='age-x25519-chacha20poly1305'),
 break_glass boolean NOT NULL DEFAULT false,
 failed_attempts integer NOT NULL DEFAULT 0 CHECK(failed_attempts>=0),
 blocked_until timestamptz NOT NULL DEFAULT '-infinity',
 last_totp_step bigint NOT NULL DEFAULT 0,
 credential_version bigint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX local_users_one_break_glass ON local_users(break_glass) WHERE break_glass;
ALTER TABLE identity_sessions DROP CONSTRAINT identity_sessions_kind_check;
ALTER TABLE identity_sessions ADD CHECK(kind IN ('oidc','local','break-glass'));
CREATE TABLE identity_settings (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 local_config jsonb NOT NULL,
 oidc_config jsonb,
 client_secret bytea,
 key_id text,
 algorithm text,
 revision bigint NOT NULL DEFAULT 1,
 deployment_hash text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE local_login_ips (
 ip_hash text PRIMARY KEY,
 window_start timestamptz NOT NULL DEFAULT now(),
 attempts integer NOT NULL DEFAULT 1
);
-- Recovery cannot be removed through older generic user/role endpoints either.
CREATE FUNCTION protect_local_recovery() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM local_users WHERE user_id=OLD.id AND break_glass) THEN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'recovery administrator cannot be deleted'; END IF;
  IF NEW.disabled OR NEW.email<>OLD.email THEN RAISE EXCEPTION 'recovery administrator must remain enabled'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER protect_local_recovery BEFORE UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION protect_local_recovery();
CREATE FUNCTION protect_recovery_role() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.role='GlobalAdmin' AND EXISTS(SELECT 1 FROM local_users WHERE user_id=OLD.user_id AND break_glass) THEN
  RAISE EXCEPTION 'recovery administrator role cannot be removed';
 END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER protect_recovery_role BEFORE UPDATE OR DELETE ON role_assignments FOR EACH ROW EXECUTE FUNCTION protect_recovery_role();
CREATE TABLE identity_session_revision (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 revision bigint NOT NULL DEFAULT 1
);
INSERT INTO identity_session_revision(singleton) VALUES(true);
CREATE FUNCTION bump_identity_session_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE identity_session_revision SET revision=revision+1 WHERE singleton;
 RETURN NULL;
END $$;
CREATE TRIGGER identity_sessions_revision AFTER INSERT OR UPDATE OR DELETE ON identity_sessions FOR EACH STATEMENT EXECUTE FUNCTION bump_identity_session_revision();
CREATE TRIGGER identity_users_revision AFTER UPDATE OR DELETE ON users FOR EACH STATEMENT EXECUTE FUNCTION bump_identity_session_revision();
CREATE TRIGGER identity_settings_revision AFTER UPDATE ON identity_settings FOR EACH STATEMENT EXECUTE FUNCTION bump_identity_session_revision();
-- +goose StatementEnd
