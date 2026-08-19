package sbom

import "testing"

const oldCDX = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "components": [
    {"type":"library","name":"a","version":"1.0"},
    {"type":"library","name":"b","version":"2.0"},
    {"type":"library","name":"c","version":"3.0"}
  ]
}`

const newCDX = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "components": [
    {"type":"library","name":"a","version":"1.1"},
    {"type":"library","name":"c","version":"3.0"},
    {"type":"library","name":"d","version":"4.0"}
  ]
}`

func TestCompare_DetectsAddedRemovedChanged(t *testing.T) {
	d, err := Compare([]byte(oldCDX), []byte(newCDX))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 1 || d.Added[0].Name != "d" {
		t.Fatalf("added: %+v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Name != "b" {
		t.Fatalf("removed: %+v", d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[0].Name != "a" {
		t.Fatalf("changed: %+v", d.Changed)
	}
	if d.Changed[0].OldVersion != "1.0" || d.Changed[0].NewVersion != "1.1" {
		t.Fatalf("version delta wrong: %+v", d.Changed)
	}
}

const spdxA = `{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {"name":"a","versionInfo":"1.0"},
    {"name":"b","versionInfo":"2.0"}
  ]
}`

const spdxB = `{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {"name":"a","versionInfo":"1.1"}
  ]
}`

func TestCompare_SPDXShape(t *testing.T) {
	d, err := Compare([]byte(spdxA), []byte(spdxB))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Removed) != 1 || d.Removed[0].Name != "b" {
		t.Fatalf("removed: %+v", d.Removed)
	}
	if len(d.Changed) != 1 {
		t.Fatalf("changed: %+v", d.Changed)
	}
}
