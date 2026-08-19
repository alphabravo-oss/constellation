package findings

import "testing"

func TestParseNVDPage(t *testing.T) {
	const fixture = `{
      "resultsPerPage": 2,
      "startIndex": 0,
      "totalResults": 2,
      "vulnerabilities": [
        {"cve": {
          "id": "CVE-2021-44228",
          "published": "2021-12-10T10:15:09.000Z",
          "lastModified": "2023-04-03T20:15:09.000Z",
          "descriptions": [
            {"lang":"es","value":"descripcion"},
            {"lang":"en","value":"Apache Log4j2 JNDI RCE."}
          ],
          "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N"}}]}
        }},
        {"cve": {
          "id": "cve-2014-0160",
          "published": "2014-04-07T22:55:03.000Z",
          "lastModified": "2023-11-07T21:59:00.000Z",
          "descriptions": [{"lang":"en","value":"Heartbleed."}],
          "metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.0/AV:N"}}]}
        }}
      ]
    }`
	rows, total, err := parseNVDPage([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("total=%d rows=%d", total, len(rows))
	}
	// English description chosen, id upper-cased, CVSS v3.1 taken.
	r0 := rows[0]
	if r0.id != "CVE-2021-44228" || r0.description != "Apache Log4j2 JNDI RCE." {
		t.Fatalf("row0: %+v", r0)
	}
	if r0.cvssBase == nil || *r0.cvssBase != 10.0 || r0.cvssVector != "CVSS:3.1/AV:N" {
		t.Fatalf("row0 cvss: %+v", r0)
	}
	if r0.published == nil || r0.modified == nil {
		t.Fatal("row0 timestamps not parsed")
	}
	// v3.0 fallback + lower-case id normalized.
	if rows[1].id != "CVE-2014-0160" || rows[1].cvssBase == nil || *rows[1].cvssBase != 7.5 {
		t.Fatalf("row1: %+v", rows[1])
	}
}
