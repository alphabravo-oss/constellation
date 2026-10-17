"""Create the local rehearsal bucket using SigV4; no external Python packages."""
import datetime
import hashlib
import hmac
import os
import urllib.error
import urllib.request

endpoint = "http://rustfs:9000"
bucket = "constellation-recovery"
region = "us-east-1"
access_key = os.environ["ACCESS_KEY_ID"]
secret_key = os.environ["SECRET_ACCESS_KEY"]
now = datetime.datetime.now(datetime.timezone.utc)
date = now.strftime("%Y%m%d")
stamp = now.strftime("%Y%m%dT%H%M%SZ")
payload_hash = hashlib.sha256(b"").hexdigest()
headers = f"host:rustfs:9000\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{stamp}\n"
signed = "host;x-amz-content-sha256;x-amz-date"
canonical = f"PUT\n/{bucket}\n\n{headers}\n{signed}\n{payload_hash}"
scope = f"{date}/{region}/s3/aws4_request"
to_sign = f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
key = ("AWS4" + secret_key).encode()
for part in [date, region, "s3", "aws4_request"]:
    key = hmac.new(key, part.encode(), hashlib.sha256).digest()
signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
request = urllib.request.Request(endpoint + "/" + bucket, data=b"", method="PUT", headers={
    "x-amz-content-sha256": payload_hash,
    "x-amz-date": stamp,
    "Authorization": f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}",
})
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        print(f"Bucket {bucket}: HTTP {response.status}")
except urllib.error.HTTPError as error:
    body = error.read().decode()
    if error.code != 409 or "BucketAlreadyOwnedByYou" not in body:
        raise RuntimeError(f"Bucket creation failed: HTTP {error.code}: {body}") from None
    print(f"Bucket {bucket} already owned by this rehearsal")
