#!/usr/bin/env python3
"""Read-only inventory for the historical admission test CA and leaf certificates.

Requests named certificate fields only in kubectl's output. Never emits or saves
certificate/key material. Other field names, files, trust stores and clusters
remain outside this inventory. A zero result is scoped evidence, not revocation.
"""
import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys


HISTORICAL_CERTIFICATES = {
    "bdbf005d3314f57858128e9ef6427e8d88dfebfffefb437445a2d48ef99c2be5": "admission-ca",
    "86093a88a19fd07838e57eaf7ce54e7a8fd7a55282460146c7e9618107b2f0c8": "admission-server",
}
HISTORICAL_PUBLIC_KEYS = {
    "b54ddd6078648c3bfb91c50ee73976315495da66cbb2d96c720ef89081646efe": "admission-ca",
    "2e843deb6e42c53a0a703ca7d0854873fbf9ba3a0ecabfed83f21c3225f99b50": "admission-server",
}
CERTIFICATE_FIELDS = ("ca.crt", "tls.crt", "ca-bundle.crt", "root-cert.pem", "cert.pem")


def certificate_fingerprints(pem):
    blocks = re.findall(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    if not blocks:
        raise ValueError("named certificate field contains no PEM certificate")
    fingerprints = []
    for block in blocks:
        result = subprocess.run(
            ["openssl", "x509", "-outform", "DER"], input=block,
            capture_output=True, timeout=5, check=False,
        )
        if result.returncode:
            raise ValueError("named certificate field contains an invalid certificate")
        certificate_digest = hashlib.sha256(result.stdout).hexdigest()
        public_key = subprocess.run(
            ["openssl", "x509", "-pubkey", "-noout"], input=block,
            capture_output=True, timeout=5, check=False,
        )
        if public_key.returncode:
            raise ValueError("certificate public key could not be extracted")
        spki = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"], input=public_key.stdout,
            capture_output=True, timeout=5, check=False,
        )
        if spki.returncode:
            raise ValueError("certificate public key could not be decoded")
        fingerprints.append((certificate_digest, hashlib.sha256(spki.stdout).hexdigest()))
    return fingerprints


def public_field_template(fields):
    template = r'{{range .items}}{{.metadata.namespace}}/{{.metadata.name}}'
    for field in fields:
        template += (r'{{"\t"}}{{if .data}}{{with index .data "' + field + '"}}'
                     '{{printf "%q" .}}{{else}}""{{end}}{{else}}""{{end}}')
    return template + r'{{"\n"}}{{end}}'


def read_records(kubectl, kind):
    if kind in ("secrets", "configmaps"):
        fields = CERTIFICATE_FIELDS
        template = public_field_template(fields)
        scope = ["--all-namespaces"]
    else:
        fields = ("caBundle",)
        scope = []
        template = ('{{range .items}}{{$kind := .kind}}{{$name := .metadata.name}}'
                    r'{{range .webhooks}}{{printf "%s/%s/%s" $kind $name .name}}{{"\t"}}'
                    '{{with .clientConfig.caBundle}}{{printf "%q" .}}{{else}}""{{end}}'
                    r'{{"\n"}}{{end}}{{end}}')
    result = subprocess.run(
        kubectl + ["get", kind] + scope + ["-o", "go-template=" + template],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode:
        raise ValueError("kubectl could not inventory " + kind)
    records = []
    for line in result.stdout.splitlines():
        columns = line.split("\t")
        if len(columns) != len(fields) + 1:
            raise ValueError("unexpected public-field output shape for " + kind)
        for field, raw in zip(fields, columns[1:]):
            value = json.loads(raw)
            if value:
                records.append((kind + ":" + columns[0], field, value, kind != "configmaps"))
    return records


def audit_records(records):
    report = {"certificate_fields_checked": 0, "certificates_checked": 0,
              "historical_certificate_matches": [], "historical_public_key_matches": [], "errors": []}
    for resource, field, value, encoded in records:
        report["certificate_fields_checked"] += 1
        try:
            pem = base64.b64decode(value, validate=True) if encoded else value.encode("utf-8")
            fingerprints = certificate_fingerprints(pem)
            report["certificates_checked"] += len(fingerprints)
            for fingerprint, public_key in fingerprints:
                if fingerprint in HISTORICAL_CERTIFICATES:
                    report["historical_certificate_matches"].append({
                        "resource": resource, "field": field,
                        "certificate": HISTORICAL_CERTIFICATES[fingerprint],
                        "sha256_der": fingerprint,
                    })
                if public_key in HISTORICAL_PUBLIC_KEYS:
                    report["historical_public_key_matches"].append({
                        "resource": resource, "field": field,
                        "key": HISTORICAL_PUBLIC_KEYS[public_key],
                        "sha256_spki": public_key,
                    })
        except (ValueError, subprocess.SubprocessError):
            # Never include field contents or command output in an error.
            report["errors"].append({"resource": resource, "field": field,
                                     "error": "certificate field could not be verified"})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--context")
    parser.add_argument("--label", default="selected-cluster")
    args = parser.parse_args()
    kubectl = ["kubectl"]
    if args.kubeconfig:
        kubectl += ["--kubeconfig", args.kubeconfig]
    if args.context:
        kubectl += ["--context", args.context]
    report = {"environment": args.label, "inventories": {}}
    failed = False
    matched = False
    for kind in ("secrets", "configmaps", "validatingwebhookconfigurations,mutatingwebhookconfigurations"):
        try:
            result = audit_records(read_records(kubectl, kind))
            failed = failed or bool(result["errors"])
            matched = matched or bool(result["historical_certificate_matches"] or result["historical_public_key_matches"])
        except (ValueError, subprocess.SubprocessError, OSError):
            result = {"error": "inventory unavailable; certificate safety is unverified"}
            failed = True
        report["inventories"][kind] = result
    print(json.dumps(report, indent=2))
    return 2 if failed else 1 if matched else 0


if __name__ == "__main__":
    sys.exit(main())
