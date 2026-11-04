//! Huawei Cloud OBS native REST client.
//!
//! Native signing only: HMAC-SHA1, `Authorization: OBS <AK>:<Base64>`,
//! `x-obs-*` headers. No SigV4 / S3 code lives in this module on purpose:
//! mixing the two signatures is the fastest way to a 403
//! `SignatureDoesNotMatch`.
//!
//! StringToSign (from the OBS API reference):
//! ```text
//! HTTP-Verb + "\n" + Content-MD5 + "\n" + Content-Type + "\n" + Date + "\n"
//!   + CanonicalizedHeaders + CanonicalizedResource
//! ```
//! CanonicalizedHeaders: `x-obs-*` headers only, lower-cased, sorted,
//! `name:value\n` each. CanonicalizedResource: `/<bucket>/<key>` plus
//! whitelisted sub-resources only (e.g. `uploads`, `uploadId`, `partNumber`,
//! `delete`), sorted and `&`-joined. Plain query parameters such as
//! `prefix`, `delimiter`, `marker`, `max-keys` are sent in the URL but do
//! NOT enter the signature.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest as _, Md5};
use quick_xml::Reader;
use quick_xml::events::Event;
use reqwest::blocking::Client;
use sha1::Sha1;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;

/// Total attempts per request (the first try plus retries). obsfs uses 3
/// retries; this is 4 attempts, close enough while backing off further.
const RETRY_ATTEMPTS: u32 = 5;
const RETRY_BASE_MS: u64 = 500;
/// Cap so a long outage cannot park a FUSE request for minutes.
const RETRY_MAX_MS: u64 = 8_000;

/// Exponential backoff: 0.5s, 1s, 2s, 4s (capped).
fn backoff_delay(attempt: u32) -> Duration {
    let ms = RETRY_BASE_MS.saturating_mul(1u64 << attempt.min(6));
    Duration::from_millis(ms.min(RETRY_MAX_MS))
}

/// Statuses worth retrying: transient server-side failures and throttling.
/// Everything else (2xx, 3xx, 4xx) is returned to the caller as-is.
fn is_retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

#[derive(Debug, Error)]
pub enum ObsError {
    #[error("HTTP {status} for {method} {path}: {body}")]
    Http {
        status: u16,
        method: String,
        path: String,
        body: String,
    },
    #[error("network: {0}")]
    Network(#[from] reqwest::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("xml: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ObsError>;

/// Sub-resources that participate in the signature (whitelist, not exhaustive
/// for bucket configuration, but complete for mount operations).
fn is_subresource(name: &str) -> bool {
    matches!(
        name,
        "acl"
            | "cors"
            | "lifecycle"
            | "location"
            | "policy"
            | "tagging"
            | "versioning"
            | "uploads"
            | "uploadId"
            | "partNumber"
            | "delete"
            | "website"
            | "storagePolicy"
            | "storageinfo"
            | "quota"
            | "encryption"
            | "response-content-type"
            | "response-content-language"
            | "response-expires"
            | "response-cache-control"
            | "response-content-disposition"
            | "response-content-encoding"
    )
}

/// Percent-encode one path segment (keeps unreserved chars, encodes the rest).
pub fn encode_segment(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

/// Encode a key, preserving `/` as the separator.
pub fn encode_key(key: &str) -> String {
    key.split('/')
        .map(encode_segment)
        .collect::<Vec<_>>()
        .join("/")
}

pub fn rfc1123_now() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

pub fn md5_base64(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    B64.encode(h.finalize())
}

pub fn obs_signature(
    sk: &str,
    method: &str,
    content_md5: &str,
    content_type: &str,
    date: &str,
    x_obs_headers: &[(String, String)],
    canonicalized_resource: &str,
) -> String {
    let mut s = String::new();
    s.push_str(method);
    s.push('\n');
    s.push_str(content_md5);
    s.push('\n');
    s.push_str(content_type);
    s.push('\n');
    s.push_str(date);
    s.push('\n');
    let mut headers: Vec<(String, String)> = x_obs_headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    headers.sort();
    for (k, v) in &headers {
        s.push_str(k);
        s.push(':');
        s.push_str(v);
        s.push('\n');
    }
    s.push_str(canonicalized_resource);
    let mut mac = HmacSha1::new_from_slice(sk.as_bytes()).expect("HMAC key length");
    mac.update(s.as_bytes());
    B64.encode(mac.finalize().into_bytes())
}

#[derive(Debug, Clone, Default)]
pub struct ObjectMeta {
    pub size: u64,
    /// Kept for logging/diagnostics; nothing branches on it yet.
    #[allow(dead_code)]
    pub last_modified: Option<String>,
    /// Same: recorded so a future conditional request can use it.
    #[allow(dead_code)]
    pub etag: Option<String>,
    /// POSIX-ish attributes persisted in object metadata. `None` means "not
    /// recorded on the object", which callers render with a default rather
    /// than pretending the object has no permissions at all.
    pub unix: Option<UnixMeta>,
    /// Every `x-obs-meta-*` header, key without the prefix, lower-case.
    /// Holds user xattrs and the symlink target as well as `unix`'s fields.
    pub x_obs_meta: Vec<(String, String)>,
}

/// The Unix attributes this program persists in object metadata.
///
/// OBS has no native permissions, but object metadata is free-form and
/// Huawei's obsfs persists exactly this information the same way (it uses
/// the S3-style `x-amz-meta-` prefix because it also serves generic S3;
/// native OBS is `x-obs-meta-`, which is what this program signs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixMeta {
    /// Full st_mode, including the file-type bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Seconds since the epoch.
    pub mtime: i64,
}

/// Metadata keys this program writes, without the `x-obs-meta-` prefix.
pub mod meta_keys {
    pub const UID: &str = "uid";
    pub const GID: &str = "gid";
    pub const MODE: &str = "mode";
    pub const MTIME: &str = "mtime";
    /// Symlink target, stored on a zero-byte object whose mode says S_IFLNK.
    pub const SYMLINK_TARGET: &str = "symlink-target";
    /// Prefix for user extended attributes: `xdg.<lowercase hex(name)>`.
    pub const XATTR_PREFIX: &str = "xdg.";
}

/// Parse the persisted Unix attributes out of an `x-obs-meta-*` list.
pub fn parse_unix_meta(meta: &[(String, String)]) -> Option<UnixMeta> {
    let get = |key: &str| {
        meta.iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.parse::<i64>().ok())
    };
    let mode = get(meta_keys::MODE)?;
    Some(UnixMeta {
        mode: mode as u32,
        uid: get(meta_keys::UID).unwrap_or(0) as u32,
        gid: get(meta_keys::GID).unwrap_or(0) as u32,
        mtime: get(meta_keys::MTIME).unwrap_or(0),
    })
}

/// Symlink target stored on an object, if any.
pub fn symlink_target(meta: &[(String, String)]) -> Option<String> {
    meta.iter()
        .find(|(k, _)| k == meta_keys::SYMLINK_TARGET)
        .map(|(_, v)| v.clone())
}

/// Render `UnixMeta` as the `x-obs-meta-*` pairs to send with a PUT/COPY.
pub fn unix_meta_headers(meta: UnixMeta) -> Vec<(String, String)> {
    let h = |k: &str, v: String| (format!("x-obs-meta-{k}"), v);
    vec![
        h(meta_keys::MODE, meta.mode.to_string()),
        h(meta_keys::UID, meta.uid.to_string()),
        h(meta_keys::GID, meta.gid.to_string()),
        h(meta_keys::MTIME, meta.mtime.to_string()),
    ]
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ListEntry {
    pub key: String,
    pub size: u64,
    pub is_dir_placeholder: bool,
}

/// What kind of bucket sits behind the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketKind {
    /// Normal object bucket: flat key space, which is what this program expects.
    Object,
    /// OBS POSIX/file bucket (parallel file system). Mounting it as if it were
    /// an object bucket would be wrong, so callers refuse.
    File,
    /// HeadBucket did not answer in a way we could interpret.
    Unknown,
}

/// Decide the bucket kind from the two headers OBS uses for it. Split out so
/// the rule is testable without a server.
pub fn classify_bucket(bucket_type: &str, fs_interface: &str) -> BucketKind {
    if bucket_type.eq_ignore_ascii_case("posix") || fs_interface.eq_ignore_ascii_case("enabled") {
        BucketKind::File
    } else {
        BucketKind::Object
    }
}

/// Bucket usage as reported by `GET /?storageinfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BucketUsage {
    pub size: Option<u64>,
    pub object_number: Option<u64>,
}

/// Bucket quota as reported by `GET /?quota`.
/// A `quota` of 0 means no quota is configured (unlimited), not "no space".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BucketQuota {
    pub quota: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct ListResult {
    pub objects: Vec<ListEntry>,
    pub prefixes: Vec<String>, // directory prefixes, each ending with '/'
    pub is_truncated: bool,
    pub next_marker: Option<String>,
}

#[derive(Clone)]
pub struct ObsClient {
    ak: String,
    sk: String,
    bucket: String,
    /// Bare endpoint host, no trailing slash, e.g.
    /// `https://obs.cn-north-4.myhuaweicloud.com`.
    endpoint: String,
    /// Whether requests put the bucket in the path (`/bucket/key`) instead of
    /// the host (`bucket.obs.../key`). obsfs exposes this as
    /// `pathrequeststyle` and switches to it automatically for IP endpoints,
    /// where `bucket.1.2.3.4` is not a resolvable name. Without it, mounting
    /// through a VPN/proxy/CNAME endpoint is impossible.
    path_style: bool,
    http: Client,
}

/// Whether an endpoint must be addressed path-style (`/bucket/key`).
///
/// Huawei's OBS service endpoint rejects path-style addressing outright with
/// `VirtualHostDomainRequired` ("Virtual host domain is required while
/// accessing a specific bucket"), so a service endpoint such as
/// `https://obs.cn-north-4.myhuaweicloud.com` must be reached as
/// `<bucket>.obs.cn-north-4.myhuaweicloud.com` instead.
///
/// Path-style is only for hosts that cannot carry the bucket as a subdomain:
///  * a bare IP address, where `bucket.10.0.0.1` cannot resolve;
///  * a custom domain in front of the bucket, where the user's own hostname
///    already points at it and prefixing the bucket name would break it.
fn needs_path_style(endpoint: &str, bucket: &str) -> bool {
    let Some(host) = host_of(endpoint) else {
        return false;
    };
    if host.starts_with(&format!("{bucket}.")) {
        return false;
    }
    // An OBS host can carry the bucket as a subdomain; a custom domain
    // cannot, so it keeps path-style.
    !is_obs_host(&host)
}

/// Whether the endpoint's host already starts with `<bucket>.`.
fn host_already_has_bucket(endpoint: &str, bucket: &str) -> bool {
    host_of(endpoint).is_some_and(|h| h.starts_with(&format!("{bucket}.")))
}

/// Rewrite a service endpoint into its virtual-hosted form:
/// `https://obs.cn-north-4.myhuaweicloud.com` becomes
/// `https://<bucket>.obs.cn-north-4.myhuaweicloud.com`.
fn virtual_host_endpoint(endpoint: &str, bucket: &str) -> String {
    let (scheme, rest) = match endpoint.split_once("://") {
        Some(parts) => parts,
        None => return endpoint.to_string(),
    };
    format!("{scheme}://{bucket}.{rest}")
}

/// Whether `host` is served by Huawei OBS itself, e.g.
/// `obs.cn-north-4.myhuaweicloud.com` or `obs-private.ap-southeast-1...`.
fn is_obs_host(host: &str) -> bool {
    host.contains("myhuaweicloud")
}

/// Extract the host (no scheme, no port, no path) from a URL.
fn host_of(endpoint: &str) -> Option<String> {
    let rest = endpoint
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(endpoint);
    let host = rest.split('/').next().unwrap_or(rest);
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Re-open files for every retry; memory use is independent of object size.
enum RequestBody {
    Bytes(Vec<u8>),
    File { path: PathBuf, len: u64 },
}

impl RequestBody {
    fn md5(&self) -> Result<String> {
        match self {
            Self::Bytes(bytes) => Ok(md5_base64(bytes)),
            Self::File { path, .. } => {
                let mut file = File::open(path)?;
                let mut hash = Md5::new();
                let mut buf = [0u8; 64 * 1024];
                loop {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hash.update(&buf[..n]);
                }
                Ok(B64.encode(hash.finalize()))
            }
        }
    }

    fn body(&self) -> Result<reqwest::blocking::Body> {
        Ok(match self {
            Self::Bytes(bytes) => bytes.clone().into(),
            Self::File { path, len } => reqwest::blocking::Body::sized(File::open(path)?, *len),
        })
    }
}

impl ObsClient {
    pub fn new(ak: String, sk: String, bucket: String, endpoint: String) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("reqwest client");
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let path_style = needs_path_style(&endpoint, &bucket);
        // Path-style keeps the endpoint as given and appends /<bucket>. The
        // virtual-hosted form has to put the bucket into the host itself, or
        // OBS answers VirtualHostDomainRequired.
        let endpoint = if path_style || host_already_has_bucket(&endpoint, &bucket) {
            endpoint
        } else {
            virtual_host_endpoint(&endpoint, &bucket)
        };
        Self {
            ak,
            sk,
            bucket,
            endpoint,
            path_style,
            http,
        }
    }

    /// Prefix that object URLs are appended to.
    fn object_base(&self) -> String {
        if self.path_style {
            format!("{}/{}", self.endpoint, self.bucket)
        } else {
            self.endpoint.clone()
        }
    }

    /// Whether requests must use path-style addressing.
    pub fn uses_path_style(&self) -> bool {
        self.path_style
    }

    #[allow(dead_code)]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Build the signed request parts for one call.
    /// `query` is the full query string (already encoded) or empty.
    /// Returns (url, authorization, date, x-obs headers).
    fn sign(
        &self,
        method: &str,
        key: &str,
        query: &str,
        content_md5: &str,
        content_type: &str,
        extra_x_obs: &[(String, String)],
    ) -> (String, String, Vec<(String, String)>) {
        let date = rfc1123_now();
        let mut x_obs: Vec<(String, String)> = vec![("x-obs-date".to_string(), date.clone())];
        for (k, v) in extra_x_obs {
            x_obs.push((k.clone(), v.clone()));
        }
        // CanonicalizedResource: /<bucket>/<encoded key>[?<sorted sub-resources>]
        //
        // The key is percent-encoded exactly as it appears in the request
        // line. OBS signs the path it received, so signing the decoded form
        // makes any key with a non-ASCII byte -- or a space, or any other
        // character encode_key touches -- fail with SignatureDoesNotMatch,
        // which this program surfaces as EACCES. ASCII keys happen to encode
        // to themselves, which is why only the CJK directories broke.
        let mut resource = format!("/{}/{}", self.bucket, encode_key(key));
        if !query.is_empty() {
            let subs: Vec<&str> = query
                .split('&')
                .filter(|p| {
                    let name = p.split('=').next().unwrap_or("");
                    is_subresource(name)
                })
                .collect();
            if !subs.is_empty() {
                let mut subs = subs;
                subs.sort();
                resource.push('?');
                resource.push_str(&subs.join("&"));
            }
        }
        let sig = obs_signature(
            &self.sk,
            method,
            content_md5,
            content_type,
            // Empty on purpose: the date travels in `x-obs-date` instead.
            // OBS fills the StringToSign Date slot only when that header is
            // absent; sending both leaves the server signing an empty slot
            // while we signed a populated one, and every request comes back
            // SignatureDoesNotMatch. The error body shows what the server
            // used: "GET\n\n\n\nx-obs-date:..." -- four newlines, no date.
            "",
            &x_obs,
            &resource,
        );
        let auth = format!("OBS {}:{}", self.ak, sig);
        let url = if query.is_empty() {
            format!("{}/{}", self.object_base(), encode_key(key))
        } else {
            format!("{}/{}?{}", self.object_base(), encode_key(key), query)
        };
        // The canonical resource above is always /<bucket>/<key>; only the
        // URL shape differs between virtual-hosted and path-style requests.
        (url, auth, x_obs)
    }

    // One call = one signed request; grouping these fields into a struct
    // would only move them one level down without making the call clearer.
    #[allow(clippy::too_many_arguments)]
    fn send(
        &self,
        method: &str,
        key: &str,
        query: &str,
        body: Option<RequestBody>,
        content_type: &str,
        extra_x_obs: &[(String, String)],
        extra_headers: &[(String, String)],
    ) -> Result<reqwest::blocking::Response> {
        let content_md5 = body
            .as_ref()
            .map(RequestBody::md5)
            .transpose()?
            .unwrap_or_default();
        // Only send Content-MD5 when there is a body; otherwise the signed
        // value must stay empty or the signature will not match.
        let (url, auth, x_obs) = self.sign(
            method,
            key,
            query,
            if body.is_some() { &content_md5 } else { "" },
            content_type,
            extra_x_obs,
        );
        let mut last_err: Option<ObsError> = None;
        // obsfs retries 3 times (S3fsCurl::retries) with a fixed delay; this
        // keeps the same attempt count but backs off exponentially, so a
        // short throttle clears quickly and a real outage is not hammered.
        for attempt in 0..RETRY_ATTEMPTS {
            let mut req = self
                .http
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    &url,
                )
                .header("Authorization", &auth);
            // No `Date` header: `x-obs-date` below carries it, and sending
            // both makes reqwest and OBS disagree about which one is
            // canonical.
            for (k, v) in &x_obs {
                req = req.header(k.as_str(), v.as_str());
            }
            for (k, v) in extra_headers {
                req = req.header(k.as_str(), v.as_str());
            }
            if !content_type.is_empty() {
                req = req.header("Content-Type", content_type);
            }
            if let Some(b) = &body {
                req = req.header("Content-MD5", &content_md5).body(b.body()?);
            }
            match req.send() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // 5xx (or 429): retry with backoff, unless this was the
                    // last try. 403 is never retried -- it means the
                    // signature or credentials are wrong and will stay wrong.
                    if status == 403 || !is_retryable_status(status) {
                        return Ok(resp);
                    }
                    if attempt + 1 == RETRY_ATTEMPTS {
                        return Ok(resp);
                    }
                    let body_text = resp.text().unwrap_or_default();
                    last_err = Some(ObsError::Http {
                        status,
                        method: method.to_string(),
                        path: key.to_string(),
                        body: body_text,
                    });
                    std::thread::sleep(backoff_delay(attempt));
                }
                Err(e) => {
                    if attempt + 1 == RETRY_ATTEMPTS {
                        return Err(ObsError::Network(e));
                    }
                    last_err = Some(ObsError::Network(e));
                    std::thread::sleep(backoff_delay(attempt));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ObsError::Other("request failed".into())))
    }

    fn check(
        resp: reqwest::blocking::Response,
        method: &str,
        key: &str,
    ) -> Result<reqwest::blocking::Response> {
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(resp)
        } else {
            let body = resp.text().unwrap_or_default();
            Err(ObsError::Http {
                status,
                method: method.to_string(),
                path: key.to_string(),
                body,
            })
        }
    }

    /// Bucket kind, as revealed by `HEAD /` (HeadBucket).
    ///
    /// OBS serves two very different things behind the same endpoint: an
    /// *object* bucket (flat key space, what this program targets) and a
    /// *POSIX/file* bucket (parallel file system semantics). A file bucket
    /// answers `HEAD /` with `x-obs-bucket-type: POSIX` and/or
    /// `x-obs-fs-file-interface: Enabled`; an object bucket sends neither.
    /// Huawei's obsfs does exactly this detection before mounting
    /// (S3fsCurl::DetectBucketTypeFromHeaders).
    ///
    /// Mounting a file bucket through this program would produce subtly wrong
    /// behaviour (placeholder objects instead of real directories, no atomic
    /// rename), so the caller is expected to refuse rather than guess.
    pub fn bucket_kind(&self) -> Result<BucketKind> {
        let resp = self.send("HEAD", "", "", None, "", &[], &[])?;
        let status = resp.status().as_u16();
        if status == 404 || status == 403 {
            // Not readable as a bucket: let the caller report the real error
            // via list_dir() instead of masking it as "object bucket".
            return Ok(BucketKind::Unknown);
        }
        let resp = Self::check(resp, "HEAD", "/")?;
        let headers = resp.headers();
        let value = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        let bucket_type = value("x-obs-bucket-type");
        let fs_interface = value("x-obs-fs-file-interface");
        Ok(classify_bucket(&bucket_type, &fs_interface))
    }

    pub fn head_object(&self, key: &str) -> Result<Option<ObjectMeta>> {
        let resp = self.send("HEAD", key, "", None, "", &[], &[])?;
        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        let resp = Self::check(resp, "HEAD", key)?;
        let headers = resp.headers();
        let size = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let x_obs_meta: Vec<(String, String)> = headers
            .iter()
            .filter_map(|(name, value)| {
                let name = name.as_str().to_ascii_lowercase();
                let key = name.strip_prefix("x-obs-meta-")?;
                Some((key.to_string(), value.to_str().ok()?.to_string()))
            })
            .collect();
        let unix = parse_unix_meta(&x_obs_meta);
        Ok(Some(ObjectMeta {
            size,
            last_modified: headers
                .get("last-modified")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            etag: headers
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim_matches('"').to_string()),
            unix,
            x_obs_meta,
        }))
    }

    pub fn list_objects(
        &self,
        prefix: &str,
        delimiter: &str,
        marker: Option<&str>,
        max_keys: usize,
    ) -> Result<ListResult> {
        let mut query = format!(
            "prefix={}&delimiter={}&max-keys={}",
            urlencoding::encode(prefix),
            urlencoding::encode(delimiter),
            max_keys
        );
        if let Some(m) = marker {
            query.push_str(&format!("&marker={}", urlencoding::encode(m)));
        }
        let resp = self.send("GET", "", &query, None, "", &[], &[])?;
        let resp = Self::check(resp, "GET", "")?;
        let text = resp.text()?;
        parse_list_xml(&text)
    }

    /// List every key under `prefix` (no delimiter), following pagination.
    pub fn list_all_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut query = format!("prefix={}&max-keys=1000", urlencoding::encode(prefix));
            if let Some(m) = &marker {
                query.push_str(&format!("&marker={}", urlencoding::encode(m)));
            }
            let resp = self.send("GET", "", &query, None, "", &[], &[])?;
            let resp = Self::check(resp, "GET", "")?;
            let text = resp.text()?;
            let page = parse_list_xml(&text)?;
            let truncated = page.is_truncated;
            let next = page.next_marker.clone();
            keys.extend(page.objects.into_iter().map(|o| o.key));
            if !truncated {
                break;
            }
            marker = next.or_else(|| keys.last().cloned());
            if marker.is_none() {
                break;
            }
        }
        Ok(keys)
    }

    /// Bucket-wide usage: `GET /?storageinfo`.
    ///
    /// Returns what OBS knows about the bucket as a whole -- total bytes
    /// stored and the object count. This is the closest thing OBS offers to
    /// "how full is it", but note it reports *used*, never *capacity*: a
    /// bucket's limit is a quota the account owns, not a fixed disk size.
    pub fn bucket_storage_info(&self) -> Result<BucketUsage> {
        let resp = self.send("GET", "", "storageinfo", None, "", &[], &[])?;
        let resp = Self::check(resp, "GET", "?storageinfo")?;
        let text = resp.text()?;
        Ok(BucketUsage {
            size: parse_tag(&text, "Size").and_then(|v| v.parse().ok()),
            object_number: parse_tag(&text, "ObjectNumber").and_then(|v| v.parse().ok()),
        })
    }

    /// Bucket storage quota: `GET /?quota`.
    ///
    /// `quota` is the configured byte limit. OBS reports 0 when no quota is
    /// set, which means "unlimited" rather than "no space" -- the opposite
    /// of what a `df` reader would assume, so callers must not treat 0 as
    /// "full".
    pub fn bucket_quota(&self) -> Result<BucketQuota> {
        let resp = self.send("GET", "", "quota", None, "", &[], &[])?;
        let resp = Self::check(resp, "GET", "?quota")?;
        let text = resp.text()?;
        Ok(BucketQuota {
            quota: parse_tag(&text, "StorageQuota").and_then(|v| v.parse().ok()),
        })
    }

    /// List one directory level (delimiter="/"), following pagination.
    pub fn list_dir(&self, dir_prefix: &str) -> Result<ListResult> {
        let mut out = ListResult::default();
        let mut marker: Option<String> = None;
        loop {
            let page = self.list_objects(dir_prefix, "/", marker.as_deref(), 1000)?;
            out.objects.extend(page.objects);
            out.prefixes.extend(page.prefixes);
            if !page.is_truncated {
                break;
            }
            marker = page.next_marker;
            if marker.is_none() {
                break;
            }
        }
        Ok(out)
    }

    pub fn get_range(&self, key: &str, start: u64, len: usize) -> Result<Vec<u8>> {
        let end = start + len as u64 - 1;
        let range = format!("bytes={start}-{end}");
        let resp = self.send(
            "GET",
            key,
            "",
            None,
            "",
            &[],
            &[("Range".to_string(), range)],
        )?;
        let resp = Self::check(resp, "GET", key)?;
        Ok(resp.bytes()?.to_vec())
    }

    /// PUT with `x-obs-meta-*` headers attached.
    pub fn put_object_with_meta(
        &self,
        key: &str,
        data: &[u8],
        meta: &[(String, String)],
    ) -> Result<()> {
        let resp = self.send(
            "PUT",
            key,
            "",
            Some(RequestBody::Bytes(data.to_vec())),
            "application/octet-stream",
            meta,
            &[],
        )?;
        Self::check(resp, "PUT", key)?;
        Ok(())
    }

    /// Rewrite an object's metadata in place without moving its bytes.
    ///
    /// OBS exposes metadata replacement only through CopyObject with
    /// `x-obs-metadata-directive: REPLACE` and the object copied onto itself,
    /// which is exactly what obsfs does for chmod/chown/setxattr
    /// (s3fs_setxattr_s3). The data is not re-uploaded, so changing a
    /// permission bit on a 100 GiB object is cheap.
    pub fn set_object_meta(&self, key: &str, meta: &[(String, String)]) -> Result<()> {
        let source = format!("/{}/{}", self.bucket, encode_key(key));
        let mut headers = vec![
            ("x-obs-copy-source".to_string(), source),
            (
                "x-obs-metadata-directive".to_string(),
                "REPLACE".to_string(),
            ),
        ];
        headers.extend_from_slice(meta);
        let resp = self.send("PUT", key, "", None, "", &headers, &[])?;
        Self::check(resp, "PUT", key)?;
        Ok(())
    }

    pub fn delete_object(&self, key: &str) -> Result<()> {
        let resp = self.send("DELETE", key, "", None, "", &[], &[])?;
        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(());
        }
        Self::check(resp, "DELETE", key)?;
        Ok(())
    }

    pub fn copy_object(&self, src_key: &str, dst_key: &str) -> Result<()> {
        let source = format!("/{}/{}", self.bucket, encode_key(src_key));
        let resp = self.send(
            "PUT",
            dst_key,
            "",
            None,
            "",
            &[("x-obs-copy-source".to_string(), source)],
            &[],
        )?;
        Self::check(resp, "PUT", dst_key)?;
        Ok(())
    }

    /// Multipart init with `x-obs-meta-*`; metadata set here ends up on the
    /// final object, which is the only chance to attach it for a large file.
    pub fn initiate_multipart_with_meta(
        &self,
        key: &str,
        meta: &[(String, String)],
    ) -> Result<String> {
        let resp = self.send("POST", key, "uploads", None, "", meta, &[])?;
        let resp = Self::check(resp, "POST", key)?;
        let text = resp.text()?;
        parse_tag(&text, "UploadId")
            .ok_or_else(|| ObsError::Other("no UploadId in response".into()))
    }

    pub fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        data: &[u8],
    ) -> Result<String> {
        let query = format!(
            "partNumber={part_number}&uploadId={}",
            urlencoding::encode(upload_id)
        );
        let resp = self.send(
            "PUT",
            key,
            &query,
            Some(RequestBody::Bytes(data.to_vec())),
            "application/octet-stream",
            &[],
            &[],
        )?;
        let resp = Self::check(resp, "PUT", key)?;
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim_matches('"')
            .to_string();
        Ok(etag)
    }

    pub fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[(u32, String)],
    ) -> Result<()> {
        let mut body = String::from("<CompleteMultipartUpload>");
        for (n, etag) in parts {
            body.push_str(&format!(
                "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
            ));
        }
        body.push_str("</CompleteMultipartUpload>");
        let query = format!("uploadId={}", urlencoding::encode(upload_id));
        let resp = self.send(
            "POST",
            key,
            &query,
            Some(RequestBody::Bytes(body.into_bytes())),
            "application/xml",
            &[],
            &[],
        )?;
        Self::check(resp, "POST", key)?;
        Ok(())
    }

    pub fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        let query = format!("uploadId={}", urlencoding::encode(upload_id));
        let resp = self.send("DELETE", key, &query, None, "", &[], &[])?;
        let _ = Self::check(resp, "DELETE", key);
        Ok(())
    }

    /// Download to a temporary file and publish it only after a complete GET.
    /// An unsuccessful or short response must never become writable staging.
    pub fn download_to(&self, key: &str, path: &Path, meta: &ObjectMeta) -> Result<()> {
        let partial = path.with_extension("download");
        let result = (|| {
            let headers = meta
                .etag
                .as_ref()
                .map(|tag| vec![("If-Match".into(), format!("\"{tag}\""))])
                .unwrap_or_default();
            let resp = self.send("GET", key, "", None, "", &[], &headers)?;
            let mut resp = Self::check(resp, "GET", key)?;
            let mut file = File::create(&partial)?;
            let copied = std::io::copy(&mut resp, &mut file)?;
            if copied != meta.size {
                return Err(ObsError::Other(format!(
                    "incomplete download: expected {}, received {copied}",
                    meta.size
                )));
            }
            file.flush()?;
            std::fs::rename(&partial, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(partial);
        }
        result
    }

    /// Upload a staging file with bounded buffers. Small PUTs also stream from
    /// disk, even when the configured multipart threshold is very large.
    pub fn upload_file_with_meta(
        &self,
        key: &str,
        path: &Path,
        tuning: UploadTuning,
        meta: &[(String, String)],
    ) -> Result<()> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        if len == 0 || len < tuning.threshold {
            let resp = self.send(
                "PUT",
                key,
                "",
                Some(RequestBody::File {
                    path: path.to_owned(),
                    len,
                }),
                "application/octet-stream",
                meta,
                &[],
            )?;
            Self::check(resp, "PUT", key)?;
            return Ok(());
        }
        let file_len = usize::try_from(len)
            .map_err(|_| ObsError::Other("file too large for this platform".into()))?;
        let part = multipart_part_size_with(file_len, tuning.part_size);
        let upload_id = self.initiate_multipart_with_meta(key, meta)?;
        let mut parts = Vec::new();
        let mut remaining = file_len;
        let mut part_no = 1;
        let mut result = Ok(());
        while remaining > 0 && result.is_ok() {
            let mut handles = Vec::new();
            for _ in 0..4 {
                if remaining == 0 {
                    break;
                }
                let mut chunk = vec![0; remaining.min(part)];
                if let Err(e) = file.read_exact(&mut chunk) {
                    result = Err(ObsError::Io(e));
                    break;
                }
                remaining -= chunk.len();
                let client = self.clone();
                let key = key.to_owned();
                let upload_id = upload_id.clone();
                let number = part_no;
                handles.push((
                    number,
                    std::thread::spawn(move || {
                        client.upload_part(&key, &upload_id, number, &chunk)
                    }),
                ));
                part_no += 1;
            }
            // Always join all workers before aborting, including read failures.
            for (number, handle) in handles {
                match handle.join() {
                    Ok(Ok(etag)) => parts.push((number, etag)),
                    Ok(Err(e)) if result.is_ok() => result = Err(e),
                    Err(_) if result.is_ok() => {
                        result = Err(ObsError::Other("part upload thread panicked".into()))
                    }
                    _ => {}
                }
            }
        }
        if result.is_ok() {
            result = self.complete_multipart(key, &upload_id, &parts);
        }
        if result.is_err() {
            let _ = self.abort_multipart(key, &upload_id);
        }
        result
    }
}

/// Extract the text of the first `<tag>...</tag>` element.
///
/// OBS always prefixes its XML responses with an `<?xml ... ?>` declaration,
/// so every event kind that is not the tag we are looking for must be
/// *skipped*, not treated as end-of-input: an early `break` on e.g.
/// `Event::Decl` made multipart uploads fail with "no UploadId in response"
/// against a real bucket.
///
/// Text is accumulated across events because character references such as
/// `&amp;` are reported as separate `Text` events, so stopping at the first
/// one would silently truncate values like `a&b`.
fn parse_tag(xml: &str, tag: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut in_tag = false;
    let mut text = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if e.name().as_ref() == tag {
                    in_tag = true;
                } else if in_tag {
                    // Nested element inside the target: not a plain value.
                    return None;
                }
            }
            Ok(Event::Text(e)) => {
                if in_tag {
                    text.push_str(&e.xml10_content());
                }
            }
            // `&amp;` and friends arrive as their own event; resolve them so
            // values containing '&' / '<' are not silently dropped.
            Ok(Event::GeneralRef(e)) => {
                if in_tag {
                    match e.resolve_char_ref() {
                        Ok(Some(ch)) => text.push(ch),
                        _ => text.push_str(
                            quick_xml::escape::resolve_predefined_entity(e.as_ref())
                                .unwrap_or(e.as_ref()),
                        ),
                    }
                }
            }
            Ok(Event::CData(e)) => {
                if in_tag {
                    text.push_str(&e.xml10_content());
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref() == tag {
                    return Some(text);
                }
            }
            // Decl, Comment, PI, DocType, ... : keep reading.
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    None
}

/// Minimal ListBucketResult parser (Contents / CommonPrefixes / IsTruncated /
/// NextMarker). Uses an event reader so the `xmlns` on the root element does
/// not matter.
pub fn parse_list_xml(xml: &str) -> Result<ListResult> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut out = ListResult::default();
    // Stack of element names; Contents/CommonPrefixes are tracked by depth.
    let mut stack: Vec<String> = Vec::new();
    let mut cur_key: Option<String> = None;
    let mut cur_size: u64 = 0;
    let mut cur_text_elem: Option<String> = None;
    let mut cur_text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_owned();
                if name == "Contents" {
                    cur_key = None;
                    cur_size = 0;
                }
                stack.push(name.clone());
                cur_text_elem = Some(name);
            }
            Ok(Event::Text(e)) => {
                if cur_text_elem.is_some() {
                    // Accumulate instead of assigning: one element can arrive
                    // as several Text events when it contains a character
                    // reference (`a&amp;b` is Text + GeneralRef + Text), and
                    // assigning would keep only the last fragment.
                    cur_text.push_str(&e.xml10_content());
                }
            }
            Ok(Event::GeneralRef(e)) => {
                if cur_text_elem.is_some() {
                    match e.resolve_char_ref() {
                        Ok(Some(ch)) => cur_text.push(ch),
                        _ => cur_text.push_str(
                            quick_xml::escape::resolve_predefined_entity(e.as_ref())
                                .unwrap_or(e.as_ref()),
                        ),
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name().as_ref().to_owned();
                if name == "Contents"
                    && let Some(key) = cur_key.take()
                {
                    out.objects.push(ListEntry {
                        is_dir_placeholder: key.ends_with('/'),
                        key,
                        size: cur_size,
                    });
                }
                // Commit the element's text now that all fragments are in.
                if let Some(elem) = cur_text_elem.take() {
                    let in_contents = stack.iter().any(|s| s == "Contents");
                    let in_prefix = stack.iter().any(|s| s == "CommonPrefixes");
                    match elem.as_str() {
                        "Key" if in_contents => cur_key = Some(std::mem::take(&mut cur_text)),
                        "Size" if in_contents => {
                            cur_size = cur_text.parse().unwrap_or(0);
                            cur_text.clear();
                        }
                        "Prefix" if in_prefix => out.prefixes.push(std::mem::take(&mut cur_text)),
                        "IsTruncated" if stack.len() == 2 => {
                            out.is_truncated = cur_text == "true";
                            cur_text.clear();
                        }
                        "NextMarker" if stack.len() == 2 => {
                            if !cur_text.is_empty() {
                                out.next_marker = Some(std::mem::take(&mut cur_text));
                            } else {
                                cur_text.clear();
                            }
                        }
                        _ => cur_text.clear(),
                    }
                }
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(ObsError::Xml(e)),
            _ => {}
        }
        buf.clear();
    }
    // OBS returns NextMarker only when truncated; fall back to the last key.
    if out.is_truncated
        && out.next_marker.is_none()
        && let Some(last) = out.objects.last()
    {
        out.next_marker = Some(last.key.clone());
    }
    Ok(out)
}

/// Canonical resource helper, exposed for unit tests.
#[allow(dead_code)]
pub fn canonical_resource(bucket: &str, key: &str, query: &str) -> String {
    let mut resource = format!("/{bucket}/{key}");
    if !query.is_empty() {
        let mut subs: Vec<&str> = query
            .split('&')
            .filter(|p| is_subresource(p.split('=').next().unwrap_or("")))
            .collect();
        subs.sort();
        if !subs.is_empty() {
            resource.push('?');
            resource.push_str(&subs.join("&"));
        }
    }
    resource
}

/// Part size for a multipart upload: 10 MB normally, growing just enough
/// that the file never needs more than 10000 parts.
/// Part size, honouring a configured base size but still growing it so a
/// huge file never needs more than 10000 parts (the per-upload limit).
pub fn multipart_part_size_with(file_len: usize, base: usize) -> usize {
    const MAX_PARTS: usize = 10_000;
    let base = base.max(5 * 1024 * 1024); // OBS minimum part size is 5 MiB
    base.max(file_len.div_ceil(MAX_PARTS))
}

/// Part size for multipart uploads: 10 MB, matching Huawei's obsfs
/// (MULTIPART_PART_SIZE in its s3fs_operations.cpp).
pub const DEFAULT_PART_SIZE: usize = 10 * 1024 * 1024;

/// Files at or above this size use multipart upload: 25 MB, matching obsfs's
/// MULTIPART_THRESHOLD.
pub const DEFAULT_MULTIPART_THRESHOLD: u64 = 25 * 1024 * 1024;

/// How large files are split for upload.
///
/// `threshold` decides single PUT vs multipart; `part_size` is the chunk size.
/// Both default to obsfs's 25 MB / 10 MB and stay configurable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadTuning {
    pub threshold: u64,
    pub part_size: usize,
}

impl Default for UploadTuning {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_MULTIPART_THRESHOLD,
            part_size: DEFAULT_PART_SIZE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_size_stays_10mb_below_limit_and_grows_above() {
        assert_eq!(
            multipart_part_size_with(30 * 1024 * 1024, DEFAULT_PART_SIZE),
            10 * 1024 * 1024
        );
        // 100 GiB would need more than 10000 10 MB parts; the size grows.
        let grown = multipart_part_size_with(100 * 1024 * 1024 * 1024, DEFAULT_PART_SIZE);
        assert!(grown > 8 * 1024 * 1024);
        assert_eq!((100usize * 1024 * 1024 * 1024).div_ceil(grown), 10_000);
    }

    #[test]
    fn subresource_filter_excludes_list_params() {
        // prefix/delimiter/marker/max-keys must NOT enter the signature.
        assert_eq!(
            canonical_resource("b", "", "prefix=a/&delimiter=/&max-keys=1000"),
            "/b/"
        );
        assert_eq!(
            canonical_resource("b", "a.txt", "partNumber=2&uploadId=xyz"),
            "/b/a.txt?partNumber=2&uploadId=xyz"
        );
    }

    #[test]
    fn signature_is_deterministic() {
        let a = obs_signature(
            "sk",
            "GET",
            "",
            "",
            "Tue, 03 Nov 2026 06:26:00 GMT",
            &[],
            "/b/a.txt",
        );
        let b = obs_signature(
            "sk",
            "GET",
            "",
            "",
            "Tue, 03 Nov 2026 06:26:00 GMT",
            &[],
            "/b/a.txt",
        );
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    /// Production OBS rejected every request with a signature that signed a
    /// populated Date slot while also sending x-obs-date. Nothing caught it
    /// because the mock preferred `Date` too. Pin the rule here.
    #[test]
    fn request_never_signs_a_date_when_x_obs_date_is_sent() {
        let client = ObsClient::new(
            "AK".into(),
            "SK".into(),
            "hkobs".into(),
            "https://obs.ap-southeast-1.myhuaweicloud.com".into(),
        );
        let (_, auth, x_obs) = client.sign("GET", "", "", "", "", &[]);
        let date = x_obs
            .iter()
            .find(|(k, _)| k == "x-obs-date")
            .map(|(_, v)| v.clone())
            .expect("x-obs-date is always sent");
        // What the client actually signed, rebuilt the way OBS rebuilds it.
        let signed_date_slot_is_empty = obs_signature("SK", "GET", "", "", "", &x_obs, "/hkobs/");
        assert_eq!(auth, format!("OBS AK:{signed_date_slot_is_empty}"));
        // Signing the date into the slot instead must produce something else,
        // otherwise this test would pass no matter what the code does.
        assert_ne!(
            obs_signature("SK", "GET", "", "", &date, &x_obs, "/hkobs/"),
            signed_date_slot_is_empty,
            "a populated Date slot must not match what OBS expects"
        );
    }

    /// A CJK key broke every request: the resource was signed decoded while
    /// OBS signs the encoded path from the request line, so `PT备份` failed
    /// with SignatureDoesNotMatch and surfaced as EACCES. ASCII keys encode to
    /// themselves, which is why only non-ASCII names broke.
    #[test]
    fn non_ascii_keys_are_signed_encoded_and_round_trip() {
        let mock = crate::test_support::MockObs::new("[]");
        let client = mock.client();
        for key in ["PT备份", "PT备份/sub dir/a.txt", "a&b/中文.txt", "sp ace"] {
            client.put_object_with_meta(key, b"payload", &[]).unwrap();
            assert!(
                mock.stats().contains("\"signature_failures\": 0"),
                "signature rejected for {key}"
            );
            let meta = client.head_object(key).unwrap().unwrap();
            assert_eq!(meta.size, 7);
            assert_eq!(client.get_range(key, 0, 7).unwrap(), b"payload");
            // Listing is what a failing `ls` actually exercises, and a
            // delimiter-ed listing only returns the first path component, so
            // list without one.
            let listed = client.list_objects("", "", None, 1000).unwrap();
            assert!(
                listed.objects.iter().any(|o| o.key == key),
                "{key} missing from listing"
            );
        }
    }

    #[test]
    fn list_xml_parses() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://obs.myhuaweicloud.com/doc/2017-01-01/">
<Name>b</Name><Prefix>backups/</Prefix><Marker></Marker><MaxKeys>1000</MaxKeys>
<IsTruncated>false</IsTruncated>
<Contents><Key>backups/a.tar.gz</Key><Size>123</Size></Contents>
<CommonPrefixes><Prefix>backups/sub/</Prefix></CommonPrefixes>
</ListBucketResult>"#;
        let r = parse_list_xml(xml).unwrap();
        assert_eq!(r.objects.len(), 1);
        assert_eq!(r.objects[0].key, "backups/a.tar.gz");
        assert_eq!(r.prefixes, vec!["backups/sub/"]);
        assert!(!r.is_truncated);
    }

    /// Regression: the `<?xml ... ?>` declaration used to abort parsing
    /// (the match fell through to a `_ => break`), so InitiateMultipart never
    /// returned an UploadId against a real OBS endpoint, which sends the
    /// declaration on every response. Every multipart upload above the
    /// threshold therefore failed with "no UploadId in response".
    #[test]
    fn parse_tag_skips_xml_declaration() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://obs.myhuaweicloud.com/doc/2017-01-01/">
<Bucket>b</Bucket><Key>k</Key><UploadId>upload-0001</UploadId>
</InitiateMultipartUploadResult>"#;
        assert_eq!(parse_tag(xml, "UploadId"), Some("upload-0001".to_string()));
    }

    #[test]
    fn parse_tag_handles_no_declaration_and_missing_tag() {
        let xml = "<R><UploadId>u1</UploadId></R>";
        assert_eq!(parse_tag(xml, "UploadId"), Some("u1".to_string()));
        assert_eq!(parse_tag(xml, "Nope"), None);
        assert_eq!(parse_tag("<R></R>", "UploadId"), None);
    }

    /// Character references arrive as separate events, so a value containing
    /// '&' must not be truncated or dropped.
    #[test]
    fn parse_tag_unescapes_entities() {
        let xml = "<R><Key>a&amp;b&lt;c</Key></R>";
        assert_eq!(parse_tag(xml, "Key"), Some("a&b<c".to_string()));
    }

    #[test]
    fn virtual_host_endpoint_keeps_virtual_host_style() {
        // The documented Huawei form: the host already starts with the bucket.
        assert!(!needs_path_style(
            "https://my-bucket.obs.cn-north-4.myhuaweicloud.com",
            "my-bucket"
        ));
        assert!(!needs_path_style(
            "https://my-bucket.obs.cn-north-4.myhuaweicloud.com/",
            "my-bucket"
        ));
    }

    #[test]
    fn service_endpoint_becomes_virtual_hosted() {
        // OBS rejects path-style on its service endpoints with
        // VirtualHostDomainRequired, so a bare service endpoint must be
        // rewritten to put the bucket in the host.
        assert!(!needs_path_style(
            "https://obs.cn-north-4.myhuaweicloud.com",
            "my-bucket"
        ));
        assert_eq!(
            virtual_host_endpoint("https://obs.cn-north-4.myhuaweicloud.com", "my-bucket"),
            "https://my-bucket.obs.cn-north-4.myhuaweicloud.com"
        );
        // Private and custom-suffix hosts are OBS too.
        assert!(!needs_path_style(
            "https://obs-private.ap-southeast-1.myhuaweicloud.com",
            "my-bucket"
        ));
    }

    #[test]
    fn ip_endpoints_use_path_style() {
        // "bucket.10.0.0.1" cannot resolve, so virtual-host style is impossible.
        assert!(needs_path_style("http://10.0.0.1", "b"));
        assert!(needs_path_style("https://192.168.1.100:8080", "b"));
        assert!(needs_path_style("http://[::1]:9000", "b"));
    }

    #[test]
    fn object_url_follows_the_addressing_style() {
        let virtual_host = ObsClient::new(
            "ak".into(),
            "sk".into(),
            "b".into(),
            "https://b.obs.cn-north-4.myhuaweicloud.com".into(),
        );
        assert!(!virtual_host.uses_path_style());
        assert_eq!(
            virtual_host.object_base(),
            "https://b.obs.cn-north-4.myhuaweicloud.com"
        );

        // A service endpoint is rewritten rather than addressed path-style.
        let service = ObsClient::new(
            "ak".into(),
            "sk".into(),
            "b".into(),
            "https://obs.cn-north-4.myhuaweicloud.com".into(),
        );
        assert!(!service.uses_path_style());
        assert_eq!(
            service.object_base(),
            "https://b.obs.cn-north-4.myhuaweicloud.com"
        );

        // A custom domain keeps path-style: prefixing it with the bucket name
        // would point at a host that does not exist.
        let custom = ObsClient::new(
            "ak".into(),
            "sk".into(),
            "b".into(),
            "https://s3.example.com".into(),
        );
        assert!(custom.uses_path_style());
        assert_eq!(custom.object_base(), "https://s3.example.com/b");
    }

    /// OBS serves POSIX/file buckets behind the same endpoint; mounting one as
    /// an object bucket would be silently wrong. Mirrors obsfs's detection.
    #[test]
    fn bucket_kind_follows_obs_headers() {
        assert_eq!(classify_bucket("POSIX", ""), BucketKind::File);
        assert_eq!(classify_bucket("posix", "Enabled"), BucketKind::File);
        assert_eq!(classify_bucket("", "enabled"), BucketKind::File);
        assert_eq!(classify_bucket("", ""), BucketKind::Object);
        assert_eq!(classify_bucket("OBJECT", "Disabled"), BucketKind::Object);
    }

    #[test]
    fn retry_classification() {
        // Transient: retry. Permanent: return immediately.
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(429));
        assert!(!is_retryable_status(403));
        assert!(!is_retryable_status(404));
        assert!(!is_retryable_status(200));
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_delay(0), Duration::from_millis(500));
        assert_eq!(backoff_delay(1), Duration::from_millis(1000));
        assert_eq!(backoff_delay(2), Duration::from_millis(2000));
        assert_eq!(backoff_delay(3), Duration::from_millis(4000));
        // Never parks a FUSE request for minutes.
        assert_eq!(backoff_delay(20), Duration::from_millis(RETRY_MAX_MS));
    }

    #[test]
    fn part_size_respects_configured_base() {
        // obsfs-style 10 MB parts.
        let ten_mb = 10 * 1024 * 1024;
        assert_eq!(multipart_part_size_with(30 * 1024 * 1024, ten_mb), ten_mb);
        // Never below the OBS 5 MiB minimum, even if configured lower.
        assert_eq!(
            multipart_part_size_with(30 * 1024 * 1024, 1024),
            5 * 1024 * 1024
        );
        // Still grows for a file that would need more than 10000 parts.
        let huge = 100usize * 1024 * 1024 * 1024;
        assert_eq!(
            huge.div_ceil(multipart_part_size_with(huge, ten_mb)),
            10_000
        );
    }

    #[test]
    fn unix_meta_round_trips_through_headers() {
        let meta = UnixMeta {
            mode: libc::S_IFREG | 0o640,
            uid: 1234,
            gid: 5678,
            mtime: 1_577_934_245,
        };
        let headers = unix_meta_headers(meta);
        // Header names must survive signing, so they are lower-case x-obs-*.
        assert!(headers.iter().all(|(k, _)| k.starts_with("x-obs-meta-")));
        let stripped: Vec<(String, String)> = headers
            .into_iter()
            .map(|(k, v)| (k.trim_start_matches("x-obs-meta-").to_string(), v))
            .collect();
        assert_eq!(parse_unix_meta(&stripped), Some(meta));
    }

    #[test]
    fn unix_meta_absent_when_mode_missing() {
        assert_eq!(parse_unix_meta(&[]), None);
        assert_eq!(
            parse_unix_meta(&[("uid".to_string(), "7".to_string())]),
            None,
            "uid alone is not enough to claim the object is annotated"
        );
    }

    #[test]
    fn list_xml_keeps_escaped_characters_in_keys() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
<IsTruncated>false</IsTruncated>
<Contents><Key>a&amp;b/中文.txt</Key><Size>7</Size></Contents>
</ListBucketResult>"#;
        let r = parse_list_xml(xml).unwrap();
        assert_eq!(r.objects.len(), 1);
        assert_eq!(r.objects[0].key, "a&b/中文.txt");
        assert_eq!(r.objects[0].size, 7);
    }

    #[test]
    fn disk_uploads_match_independent_source_for_put_and_multipart() {
        // First streamed PUT is retried: a retry must reopen the file at zero.
        let mock =
            crate::test_support::MockObs::new(r#"[{"method":"PUT","key":"single","status":500}]"#);
        let client = mock.client();
        let source = mock.staging.join("source");
        let expected: Vec<u8> = (0..(26 * 1024 * 1024 + 7))
            .map(|n| (n % 251) as u8)
            .collect();
        std::fs::write(&source, &expected).unwrap();
        for (key, threshold) in [("single", u64::MAX), ("multipart", 1)] {
            client
                .upload_file_with_meta(
                    key,
                    &source,
                    UploadTuning {
                        threshold,
                        part_size: 5 * 1024 * 1024,
                    },
                    &[],
                )
                .unwrap();
            let meta = client.head_object(key).unwrap().unwrap();
            assert_eq!(meta.size, expected.len() as u64);
            let downloaded = mock.staging.join(format!("download-{key}"));
            client.download_to(key, &downloaded, &meta).unwrap();
            assert_eq!(
                md5_base64(&std::fs::read(downloaded).unwrap()),
                md5_base64(&expected)
            );
        }
        // Empty files must use a valid zero-length PUT even at threshold 1.
        std::fs::write(&source, []).unwrap();
        client
            .upload_file_with_meta(
                "empty",
                &source,
                UploadTuning {
                    threshold: 1,
                    part_size: DEFAULT_PART_SIZE,
                },
                &[],
            )
            .unwrap();
        assert_eq!(client.head_object("empty").unwrap().unwrap().size, 0);
        assert!(mock.stats().contains("\"signature_failures\": 0"));
    }

    #[test]
    fn multipart_failure_aborts_all_parts_and_keeps_source() {
        let mock = crate::test_support::MockObs::new(
            r#"[{"method":"PUT","key":"backup","query":"partNumber","status":403}]"#,
        );
        let source = mock.staging.join("source");
        File::create(&source)
            .unwrap()
            .set_len(26 * 1024 * 1024)
            .unwrap();
        let client = mock.client();
        assert!(
            client
                .upload_file_with_meta("backup", &source, UploadTuning::default(), &[])
                .is_err()
        );
        assert!(source.exists());
        assert!(client.head_object("backup").unwrap().is_none());
        assert!(mock.stats().contains("\"uploads\": 0"));
    }

    #[test]
    fn changed_or_short_download_is_not_published() {
        let mock = crate::test_support::MockObs::new("[]");
        let client = mock.client();
        client
            .put_object_with_meta("backup", b"original", &[])
            .unwrap();
        let meta = client.head_object("backup").unwrap().unwrap();
        client
            .put_object_with_meta("backup", b"changed", &[])
            .unwrap();
        let target = mock.staging.join("staged");
        assert!(client.download_to("backup", &target, &meta).is_err());
        assert!(!target.exists());
        let mut meta = client.head_object("backup").unwrap().unwrap();
        meta.size += 1;
        assert!(client.download_to("backup", &target, &meta).is_err());
        assert!(!target.exists());
        assert!(!target.with_extension("download").exists());
    }
}
