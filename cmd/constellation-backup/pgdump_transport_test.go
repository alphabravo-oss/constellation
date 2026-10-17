package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgservicefile"
)

func TestLibpqURIAndKeywordOptionsRemainExact(t *testing.T) {
	uri := "postgresql://user:p%27ass@host1:5432,[::1]:5444/database%20name?sslmode=verify-full&sslrootcert=%2Fprivate%2Froot.pem&options=-c%20search_path%3Dpublic&application_name=plus+literal"
	got, err := parseLibpqDSN(uri)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"user": "user", "password": "p'ass", "host": "host1,::1", "port": "5432,5444", "dbname": "database name", "sslmode": "verify-full", "sslrootcert": "/private/root.pem", "options": "-c search_path=public", "application_name": "plus+literal"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("URI options changed")
	}
	keyword := `user=user password='p\'ass' host='host1,::1' port=5432,5444 dbname='database name' sslmode=verify-full sslrootcert=/private/root.pem options='-c search_path=public' application_name=plus+literal`
	second, err := parseLibpqDSN(keyword)
	if err != nil || !reflect.DeepEqual(second, want) {
		t.Fatal("keyword options changed")
	}
	socket, err := parseLibpqDSN("postgresql://%2Fvar%2Frun%2Fpostgresql/db?ssl=true")
	if err != nil || socket["host"] != "/var/run/postgresql" || socket["sslmode"] != "require" {
		t.Fatal("Unix socket/JDBC option changed")
	}
}
func TestLibpqMalformedOrUnrepresentableOptionsFailCategorically(t *testing.T) {
	for _, raw := range []string{"host='unterminated", "postgresql://user:fixture-secret@host/db?sslmode=%zz", "password=fixture-secret host=bad\x00host"} {
		if _, err := parseLibpqDSN(raw); err == nil || strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal("invalid DSN accepted/leaked")
		}
	}
	t.Setenv("PGSERVICE", "")
	t.Setenv("PGSERVICEFILE", "")
	if _, err := pgDumpEnvironment(t.Context(), "host=' leading' password=fixture-secret", t.TempDir()); err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatal("lossy service representation accepted")
	}
}
func TestLibpqInheritedServiceAndPassfilePrecedence(t *testing.T) {
	directory := t.TempDir()
	profile := filepath.Join(directory, "existing.conf")
	passfile := filepath.Join(directory, "passfile")
	if err := os.WriteFile(profile, []byte("[existing]\nhost=service-host\nport=5544\ndbname=service-db\nsslmode=verify-full\nsslrootcert=/private/root.pem\npassword=service-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGSERVICEFILE", profile)
	t.Setenv("PGSERVICE", "existing")
	t.Setenv("PGPASSFILE", passfile)
	t.Setenv("PGPASSWORD", "old-password")
	env, err := pgDumpEnvironment(t.Context(), "dbname=explicit-db password=' exact password '", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		values[k] = v
	}
	if values["PGPASSWORD"] != " exact password " || values["PGPASSFILE"] != passfile || values["PGSERVICE"] != "" {
		t.Fatal("service/password/passfile precedence changed")
	}
	sf, err := pgservicefile.ReadServicefile(values["PGSERVICEFILE"])
	if err != nil {
		t.Fatal(err)
	}
	service, err := sf.GetService("constellation_backup")
	if err != nil {
		t.Fatal(err)
	}
	if service.Settings["host"] != "service-host" || service.Settings["dbname"] != "explicit-db" || service.Settings["sslmode"] != "verify-full" || service.Settings["password"] != "" {
		t.Fatal("service fields or credential boundary changed")
	}
}

func TestMalformedInheritedServiceDoesNotFallThroughToAnotherTarget(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".pg_service.conf"), []byte("malformed-user-service-with-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	system := t.TempDir()
	if err := os.WriteFile(filepath.Join(system, "pg_service.conf"), []byte("[database]\nhost=wrong-fallback-target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PGSYSCONFDIR", system)
	t.Setenv("PGSERVICEFILE", "")
	t.Setenv("PGSERVICE", "database")
	if _, err := pgDumpEnvironment(t.Context(), "", t.TempDir()); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("malformed service changed target or exposed input")
	}
}

func TestBoundedServiceReadRequiresCompleteInput(t *testing.T) {
	prefix := "[database]\nhost=first\n"
	valid := prefix + strings.Repeat("#\n", (maxLibpqServiceFileBytes-len(prefix))/2)
	if len(valid) < maxLibpqServiceFileBytes {
		valid += "#"
	}
	settings, err := parseBoundedLibpqService(strings.NewReader(valid), "database")
	if err != nil || settings["host"] != "first" {
		t.Fatal("complete service at the exact bound was rejected")
	}
	// A bounded reader used directly by the parser would accept the valid
	// prefix and silently lose this later target override after stat/growth.
	overflow := valid + "\nhost=second\n"
	partial, controlErr := pgservicefile.ParseServicefile(io.LimitReader(strings.NewReader(overflow), maxLibpqServiceFileBytes+1))
	if controlErr != nil {
		t.Fatal("negative control prefix was not syntactically complete")
	}
	selected, controlErr := partial.GetService("database")
	if controlErr != nil || selected.Settings["host"] != "first" {
		t.Fatal("negative control did not reproduce omitted target override")
	}
	settings, err = parseBoundedLibpqService(strings.NewReader(overflow), "database")
	if err == nil || settings != nil {
		t.Fatal("over-limit valid prefix silently selected a target")
	}
	reader := io.MultiReader(strings.NewReader(prefix), failingServiceRead{})
	settings, err = parseBoundedLibpqService(reader, "database")
	if err == nil || settings != nil || strings.Contains(err.Error(), "fixture-service-secret") {
		t.Fatal("incomplete read selected a target or disclosed reader details")
	}
}

type failingServiceRead struct{}

func (failingServiceRead) Read([]byte) (int, error) {
	return 0, errors.New("fixture-service-secret")
}
