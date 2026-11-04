#!/usr/bin/env python3
"""Minimal OBS-compatible mock server that VERIFIES HMAC-SHA1 OBS signatures.

Run: python3 tests/mock_obs.py [port]      (default 8899)
Then point obs-mount at it:
  endpoint: http://127.0.0.1:8899
  bucket:   test-bucket
  ak:       TESTAK
  sk:       TESTSK
`GET /__stats` returns {"signature_failures": N, "objects": N, "uploads": N}.

Implements just enough of the Huawei OBS native REST API for obs-mount:
ListObjects (prefix/delimiter/marker/max-keys), HEAD/GET(range)/PUT/DELETE object,
CopyObject (x-obs-copy-source), InitiateMultipart/UploadPart/CompleteMultipart/AbortMultipart.

Signature verification follows the documented rules:
  StringToSign = VERB\nContent-MD5\nContent-Type\nDate\nCanonicalizedHeaders\nCanonicalizedResource
Any mismatch -> 403 SignatureDoesNotMatch (exactly what real OBS does).
"""
import base64, hashlib, hmac, html, json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, quote, unquote

BUCKET = "test-bucket"
AK = "TESTAK"
SK = "TESTSK"

OBJECTS = {}          # key -> bytes
META = {}             # key -> {'mtime': str}
UPLOADS = {}          # upload_id -> {'key':..., 'parts': {n: bytes}}
OBJ_META = {}         # key -> {lower-case x-obs-meta-* headers}
pending_meta = {}     # upload_id -> metadata to apply at CompleteMultipartUpload
QUOTA = int(os.environ.get("OBS_MOCK_QUOTA", "0"))  # bytes; 0 = no quota set
# "posix" makes HEAD / report x-obs-bucket-type: POSIX, i.e. an OBS file bucket
BUCKET_TYPE = os.environ.get("OBS_MOCK_BUCKET_TYPE", "object")
_lock = threading.Lock()
_seq = [0]

SUBRES = {
    "acl", "cors", "lifecycle", "location", "policy", "tagging", "versioning",
    "uploads", "uploadId", "partNumber", "delete", "website", "storagePolicy",
    "quota", "storageinfo", "encryption", "response-content-type", "response-content-language",
    "response-expires", "response-cache-control", "response-content-disposition",
    "response-content-encoding",
}

FAULTS = json.loads(os.environ.get("OBS_MOCK_FAULTS", "[]"))

FAILURES = []         # list of strings, dumped at exit / on /__stats


def canonicalized_resource(path, raw_query):
    # path is the raw (percent-encoded) request path, e.g. /bucket/a%20b.txt
    # virtual-host style: the bucket is NOT in the URL path
    bucket = BUCKET
    key = unquote(path[1:]) if len(path) > 1 else ""
    if key == BUCKET:
        key = ""
    elif key.startswith(BUCKET + "/"):
        key = key[len(BUCKET) + 1:]
    res = f"/{bucket}/{key}"
    subs = []
    if raw_query:
        for part in raw_query.split("&"):
            name = part.split("=", 1)[0]
            if name in SUBRES:
                subs.append(part)
    subs.sort()
    if subs:
        res += "?" + "&".join(subs)
    return res


def expected_signature(handler, raw_path, raw_query, body, scheme="OBS"):
    verb = handler.command
    content_md5 = handler.headers.get("Content-MD5", "") or ""
    content_type = handler.headers.get("Content-Type", "") or ""
    # Real OBS leaves the Date slot empty whenever x-obs-date is present, and
    # dates only through the header. Preferring `Date` here (as this fixture
    # used to) hides a client that signs a populated Date slot: the fixture
    # agrees with it while production OBS rejects every request.
    date = ""
    if not handler.headers.get("x-obs-date"):
        date = handler.headers.get("Date", "") or ""
    xobs = []
    # OBS native signing covers x-obs-*; the S3-compatible flavour obsfs uses
    # covers x-amz-*. Whichever prefix the caller signs with must be the same
    # one that reaches the canonicalized headers.
    prefix = "x-obs-" if scheme == "OBS" else "x-amz-"
    for k, v in handler.headers.items():
        lk = k.lower()
        if lk.startswith(prefix):
            xobs.append(f"{lk}:{v.strip()}")
    xobs.sort()
    canon_headers = "".join(h + "\n" for h in xobs)
    res = canonicalized_resource(raw_path, raw_query)
    sts = f"{verb}\n{content_md5}\n{content_type}\n{date}\n{canon_headers}{res}"
    sig = base64.b64encode(
        hmac.new(SK.encode(), sts.encode(), hashlib.sha1).digest()
    ).decode()
    return sig, sts


def parse_qs_strict(raw_query):
    """Like parse_qs but does NOT treat '+' as space (OBS uses %20)."""
    out = {}
    if not raw_query:
        return out
    for part in raw_query.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        out.setdefault(unquote(k), []).append(unquote(v))
    return out


def xml_escape(s):
    return html.escape(s, quote=False)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        pass

    def logreq(self, status):
        if os.environ.get("OBS_MOCK_VERBOSE"):
            sys.stderr.write(f"{self.command} {self.path} -> {status}\n")
            sys.stderr.flush()
        # Optional request log for debugging a failing run:
        #   OBS_MOCK_ACCESS_LOG=/tmp/access.log python3 tests/mock_obs.py
        path = os.environ.get("OBS_MOCK_ACCESS_LOG")
        if not path:
            return
        with open(path, "a") as f:
            f.write(f"{self.command} {self.path} -> {status}\n")

    # ---------- auth ----------
    def check_auth(self, body):
        key, query, _ = self.route()
        with _lock:
            for fault in FAULTS:
                if (fault["method"] == self.command and fault["key"] == key
                        and fault.get("count", 1) > 0
                        and ("query" not in fault or fault["query"] in query)):
                    fault["count"] = fault.get("count", 1) - 1
                    self.send_empty(fault["status"])
                    return False
        auth = self.headers.get("Authorization", "")
        raw_path, raw_query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        # Content-MD5 must match body when present
        cmd5 = self.headers.get("Content-MD5")
        if body and cmd5:
            got = base64.b64encode(hashlib.md5(body).digest()).decode()
            if got != cmd5:
                FAILURES.append(f"Content-MD5 mismatch for {self.command} {raw_path}")
                return False
        # "OBS <ak>:<sig>" is native OBS; "AWS <ak>:<sig>" is the S3-compatible
        # form used by Huawei's own obsfs, needed here so both clients can be
        # benchmarked against this server.
        scheme = auth.split(" ", 1)[0] if " " in auth else ""
        if scheme not in ("OBS", "AWS"):
            FAILURES.append(f"bad auth scheme: {auth!r}")
            self.send_error_xml(403, "AccessDenied", "missing OBS auth")
            return False
        try:
            ak, sig = auth[len(scheme) + 1:].split(":", 1)
        except ValueError:
            FAILURES.append(f"malformed auth: {auth!r}")
            self.send_error_xml(403, "AccessDenied", "malformed")
            return False
        if ak != AK:
            FAILURES.append(f"unknown AK {ak}")
            self.send_error_xml(403, "InvalidAccessKeyId", "unknown ak")
            return False
        want, sts = expected_signature(self, raw_path, raw_query, body, scheme)
        if sig != want:
            FAILURES.append(
                f"SIGNATURE MISMATCH {self.command} {self.path}\n"
                f"--- got sig ---\n{sig}\n--- want sig ---\n{want}\n--- STS ---\n{sts}"
            )
            self.send_error_xml(403, "SignatureDoesNotMatch", "sig mismatch")
            return False
        return True

    # ---------- helpers ----------
    def send_xml(self, code, payload):
        self.logreq(code)
        data = payload.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_error_xml(self, code, c, msg):
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f"<Error><Code>{c}</Code><Message>{msg}</Message></Error>"
        )
        self.send_xml(code, payload)

    def send_empty(self, code, extra=None):
        self.logreq(code)
        self.send_response(code)
        self.send_header("Content-Length", "0")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def read_body(self):
        te = self.headers.get("Transfer-Encoding")
        if te and "chunked" in te.lower():
            return self.read_chunked()
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        return self.rfile.read(n) if n else b""

    def read_chunked(self):
        """Minimal chunked-body reader; reqwest may stream without a length."""
        body = b""
        while True:
            line = self.rfile.readline().strip()
            if not line:
                break
            try:
                size = int(line, 16)
            except ValueError:
                break
            if size == 0:
                self.rfile.readline()
                break
            body += self.rfile.read(size)
            self.rfile.read(2)  # CRLF
        return body

    def route(self):
        raw_path, raw_query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        key = unquote(raw_path[1:]) if len(raw_path) > 1 else ""
        # Path-style addressing puts the bucket as the first path segment:
        #   /test-bucket/key   instead of   /key
        if key == BUCKET:
            key = ""
        elif key.startswith(BUCKET + "/"):
            key = key[len(BUCKET) + 1:]
        return key, parse_qs_strict(raw_query), raw_query

    # ---------- HTTP verbs ----------
    def do_GET(self):
        if self.path == "/__stats":
            # Unauthenticated introspection, used by tests/e2e.sh to assert
            # that every request carried a valid signature.
            payload = (
                f'{{"signature_failures": {len(FAILURES)}, '
                f'"objects": {len(OBJECTS)}, "uploads": {len(UPLOADS)}}}'
            )
            data = payload.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        body = self.read_body()
        if not self.check_auth(body):
            return
        r = self.route()
        if not r:
            return
        key, q, _ = r
        with _lock:
            if key == "" and "storageinfo" in q:
                return self.bucket_storageinfo()
            if key == "" and "quota" in q:
                return self.bucket_quota()
            if key == "":
                return self.list_objects(q)
            if key not in OBJECTS:
                self.send_error_xml(404, "NoSuchKey", key)
                return
            data = OBJECTS[key]
            etag = hashlib.md5(data).hexdigest()
            if self.headers.get("If-Match") not in (None, f'"{etag}"'):
                self.send_empty(412)
                return
            rng = self.headers.get("Range")
            if rng and rng.startswith("bytes="):
                a, _, b = rng[6:].partition("-")
                start = int(a) if a else 0
                end = int(b) if b else len(data) - 1
                chunk = data[start:end + 1]
                self.send_response(206)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(chunk)))
                self.send_header("ETag", '"%s"' % etag)
                self.send_header("Last-Modified", META[key])
                self.send_header("Content-Range", f"bytes {start}-{start+len(chunk)-1}/{len(data)}")
                self.end_headers()
                self.wfile.write(chunk)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("ETag", '"%s"' % etag)
            self.send_header("Last-Modified", META[key])
            self.end_headers()
            self.wfile.write(data)

    def do_HEAD(self):
        if not self.check_auth(b""):
            return
        r0 = self.route()
        if r0 and r0[0] == "":
            # HeadBucket: used by obs-mount to reject POSIX/file buckets.
            self.logreq(200)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            if BUCKET_TYPE == "posix":
                self.send_header("x-obs-bucket-type", "POSIX")
                self.send_header("x-obs-fs-file-interface", "Enabled")
            self.end_headers()
            return
        r = self.route()
        if not r:
            return
        key, _, _ = r
        with _lock:
            if key not in OBJECTS:
                self.logreq(404)
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            data = OBJECTS[key]
            self.logreq(200)
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("ETag", '"%s"' % hashlib.md5(data).hexdigest())
            self.send_header("Last-Modified", META[key])
            for mk, mv in OBJ_META.get(key, {}).items():
                self.send_header(mk, mv)
            self.end_headers()

    def do_PUT(self):
        body = self.read_body()
        if not self.check_auth(body):
            return
        r = self.route()
        if not r:
            return
        key, q, _ = r
        with _lock:
            if "partNumber" in q and "uploadId" in q:
                uid = q["uploadId"][0]
                if uid not in UPLOADS:
                    self.send_error_xml(404, "NoSuchUpload", uid)
                    return
                n = int(q["partNumber"][0])
                UPLOADS[uid]["parts"][n] = body
                etag = hashlib.md5(body).hexdigest()
                self.send_empty(200, {"ETag": '"%s"' % etag})
                return
            src = self.headers.get("x-obs-copy-source")
            if src:
                src_key = unquote(src.lstrip("/").split("/", 1)[1])
                if os.environ.get("OBS_MOCK_VERBOSE"):
                    sys.stderr.write(f"COPY src={src_key!r} dst={key!r} present={src_key in OBJECTS}\n")
                    sys.stderr.flush()
                if src_key not in OBJECTS:
                    self.send_error_xml(404, "NoSuchKey", src_key)
                    return
                OBJECTS[key] = OBJECTS[src_key]
                META[key] = META[src_key]
                directive = (self.headers.get("x-obs-metadata-directive") or "").upper()
                if directive == "REPLACE":
                    # Metadata replacement keeps the body, swaps the headers.
                    OBJ_META[key] = {
                        k.lower(): v for k, v in self.headers.items()
                        if k.lower().startswith("x-obs-meta-")
                    }
                else:
                    OBJ_META[key] = dict(OBJ_META.get(src_key, {}))
                self.send_xml(200, "<CopyObjectResult><ETag>\"x\"</ETag></CopyObjectResult>")
                return
            OBJECTS[key] = body
            META[key] = self.date_header()
            # x-obs-meta-* is user metadata and must round-trip on HEAD.
            OBJ_META[key] = {
                k.lower(): v for k, v in self.headers.items()
                if k.lower().startswith("x-obs-meta-")
            }
            self.send_empty(200, {"ETag": '"%s"' % hashlib.md5(body).hexdigest()})

    def do_POST(self):
        body = self.read_body()
        if not self.check_auth(body):
            return
        r = self.route()
        if not r:
            return
        key, q, _ = r
        with _lock:
            if "uploads" in q:
                _seq[0] += 1
                uid = f"upload-{_seq[0]:04d}"
                pending_meta[uid] = {
                    k.lower(): v for k, v in self.headers.items()
                    if k.lower().startswith("x-obs-meta-")
                }
                UPLOADS[uid] = {"key": key, "parts": {}}
                self.send_xml(
                    200,
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    f"<InitiateMultipartUploadResult><Bucket>{BUCKET}</Bucket>"
                    f"<Key>{xml_escape(key)}</Key><UploadId>{uid}</UploadId>"
                    "</InitiateMultipartUploadResult>",
                )
                return
            if "uploadId" in q:
                uid = q["uploadId"][0]
                if uid not in UPLOADS:
                    self.send_error_xml(404, "NoSuchUpload", uid)
                    return
                up = UPLOADS.pop(uid)
                text = body.decode("utf-8", "replace")
                nums = []
                import re
                for m in re.finditer(r"<PartNumber>(\d+)</PartNumber>", text):
                    nums.append(int(m.group(1)))
                if not nums:
                    self.send_error_xml(400, "MalformedXML", "no parts")
                    return
                if sorted(nums) != list(range(1, len(nums) + 1)):
                    self.send_error_xml(400, "InvalidPartOrder", str(nums))
                    return
                data = b"".join(up["parts"][n] for n in sorted(nums))
                OBJECTS[key] = data
                META[key] = self.date_header()
                OBJ_META[key] = pending_meta.pop(uid, {})
                self.send_xml(
                    200,
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    f"<CompleteMultipartUploadResult><Key>{xml_escape(key)}</Key>"
                    f"<ETag>\"{hashlib.md5(data).hexdigest()}-{len(nums)}\"</ETag>"
                    "</CompleteMultipartUploadResult>",
                )
                return
            self.send_error_xml(400, "BadRequest", "unsupported POST")

    def do_DELETE(self):
        if not self.check_auth(b""):
            return
        r = self.route()
        if not r:
            return
        key, q, _ = r
        with _lock:
            if "uploadId" in q:
                UPLOADS.pop(q["uploadId"][0], None)
                self.send_empty(204)
                return
            if key in OBJECTS:
                del OBJECTS[key]
                META.pop(key, None)
                self.send_empty(204)
            else:
                self.send_error_xml(404, "NoSuchKey", key)

    # ---------- listing ----------
    def list_objects(self, q):
        prefix = q.get("prefix", [""])[0]
        delim = q.get("delimiter", [""])[0]
        marker = q.get("marker", [""])[0]
        max_keys = int(q.get("max-keys", ["1000"])[0])
        keys = sorted(k for k in OBJECTS if k.startswith(prefix) and k > marker)
        contents, prefixes, seen = [], [], set()
        count = 0
        truncated = False
        next_marker = None
        for k in keys:
            if delim:
                rest = k[len(prefix):]
                if delim in rest:
                    p = prefix + rest.split(delim)[0] + delim
                    if p in seen:
                        continue
                    if count >= max_keys:
                        truncated = True
                        next_marker = k
                        break
                    seen.add(p)
                    prefixes.append(p)
                    count += 1
                    continue
            if count >= max_keys:
                truncated = True
                next_marker = k
                break
            contents.append(k)
            count += 1
        parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<ListBucketResult xmlns="http://obs.myhuaweicloud.com/doc/2017-01-01/">',
            f"<Name>{BUCKET}</Name><Prefix>{xml_escape(prefix)}</Prefix>",
            f"<Marker>{xml_escape(marker)}</Marker>",
            f"<MaxKeys>{max_keys}</MaxKeys>",
            f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>",
        ]
        if next_marker:
            parts.append(f"<NextMarker>{xml_escape(next_marker)}</NextMarker>")
        for k in contents:
            parts.append(
                f"<Contents><Key>{xml_escape(k)}</Key>"
                f"<LastModified>{META[k]}</LastModified>"
                f"<Size>{len(OBJECTS[k])}</Size>"
                f"<ETag>\"{hashlib.md5(OBJECTS[k]).hexdigest()}\"</ETag>"
                f"<StorageClass>STANDARD</StorageClass></Contents>"
            )
        for p in prefixes:
            parts.append(f"<CommonPrefixes><Prefix>{xml_escape(p)}</Prefix></CommonPrefixes>")
        parts.append("</ListBucketResult>")
        self.send_xml(200, "".join(parts))

    def bucket_storageinfo(self):
        """GET /?storageinfo -- used size and object count for the bucket."""
        total = sum(len(v) for v in OBJECTS.values())
        self.send_xml(
            200,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<GetBucketStorageInfoResult>"
            f"<Location>cn-north-4</Location><Bucket>{BUCKET}</Bucket>"
            f"<Size>{total}</Size><ObjectNumber>{len(OBJECTS)}</ObjectNumber>"
            "</GetBucketStorageInfoResult>",
        )

    def bucket_quota(self):
        """GET /?quota -- configured byte quota; 0 means no quota is set."""
        self.send_xml(
            200,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            f"<Quota><StorageQuota>{QUOTA}</StorageQuota></Quota>",
        )

    def date_header(self):
        import email.utils, time
        return email.utils.formatdate(time.time(), usegmt=True)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    print(f"mock obs on 127.0.0.1:{srv.server_port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    if FAILURES:
        print("SIGNATURE/AUTH FAILURES:", len(FAILURES), flush=True)
        for f in FAILURES[:5]:
            print(f, flush=True)


if __name__ == "__main__":
    main()
