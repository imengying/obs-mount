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
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use std::time::Duration;
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;

/// Total attempts per request: one initial attempt and four retries.
const RETRY_ATTEMPTS: u32 = 5;
pub const MAX_SINGLE_SIZE: u64 = 5 * 1024 * 1024 * 1024;
pub const MIN_PART_SIZE: usize = 100 * 1024;
pub const MAX_OBJECT_SIZE: u64 = MAX_SINGLE_SIZE * 10_000;
pub const MAX_METADATA_SIZE: usize = 8 * 1024;
const SYSTEM_METADATA: &[&str] = &[
    "content-type",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "expires",
    "x-obs-storage-class",
    "x-obs-website-redirect-location",
];

pub fn validate_metadata(meta: &[(String, String)]) -> Result<()> {
    let size: usize = meta
        .iter()
        .filter_map(|(k, v)| {
            k.strip_prefix("x-obs-meta-")
                .map(|name| name.len() + v.len())
        })
        .sum();
    if size > MAX_METADATA_SIZE {
        return Err(ObsError::Io(std::io::Error::from_raw_os_error(libc::E2BIG)));
    }
    Ok(())
}

const RETRY_BASE_MS: u64 = 500;
/// Maximum delay between attempts.
const RETRY_MAX_MS: u64 = 8_000;

/// Exponential backoff: 0.5s, 1s, 2s, 4s (capped).
fn backoff_delay(attempt: u32) -> Duration {
    let ms = RETRY_BASE_MS.saturating_mul(1u64 << attempt.min(6));
    Duration::from_millis(ms.min(RETRY_MAX_MS))
}

fn retry_delay(attempt: u32) -> Duration {
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64
        % 251;
    backoff_delay(attempt) + Duration::from_millis(jitter)
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
    #[error("incomplete response: {0}")]
    Incomplete(String),
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
            | "metadata"
            | "versionId"
            | "response-content-type"
            | "response-content-language"
            | "response-expires"
            | "response-cache-control"
            | "response-content-disposition"
            | "response-content-encoding"
    )
}

/// Percent-encode one path segment (keeps unreserved chars, encodes the rest).
fn encode_segment(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

/// Encode a key, preserving `/` as the separator.
fn encode_key(key: &str) -> String {
    key.split('/')
        .map(encode_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn rfc1123_now() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

pub fn md5_base64(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    B64.encode(h.finalize())
}

fn obs_signature(
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
    pub last_modified: Option<String>,
    pub etag: Option<String>,
    /// POSIX-ish attributes persisted in object metadata. `None` means "not
    /// recorded on the object", which callers render with a default rather
    /// than pretending the object has no permissions at all.
    pub unix: Option<UnixMeta>,
    /// Every `x-obs-meta-*` header, key without the prefix, lower-case.
    /// Holds user xattrs and the symlink target as well as `unix`'s fields.
    pub x_obs_meta: Vec<(String, String)>,
    pub system_meta: Vec<(String, String)>,
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
fn parse_unix_meta(meta: &[(String, String)]) -> Option<UnixMeta> {
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
fn classify_bucket(bucket_type: &str, fs_interface: &str) -> BucketKind {
    if bucket_type.eq_ignore_ascii_case("posix") || fs_interface.eq_ignore_ascii_case("enabled") {
        BucketKind::File
    } else {
        BucketKind::Object
    }
}

#[derive(Debug, Clone, Default)]
pub struct ListResult {
    pub keys: Vec<String>,
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
    request_timeout: Duration,
    transfer_timeout: Duration,
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
    File {
        path: PathBuf,
        offset: u64,
        len: u64,
    },
}

impl RequestBody {
    fn md5(&self) -> Result<String> {
        match self {
            Self::Bytes(bytes) => Ok(md5_base64(bytes)),
            Self::File { path, offset, len } => {
                let mut file = File::open(path)?;
                file.seek(SeekFrom::Start(*offset))?;
                let mut file = file.take(*len);
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
            Self::File { path, offset, len } => {
                let mut file = File::open(path)?;
                file.seek(SeekFrom::Start(*offset))?;
                reqwest::blocking::Body::sized(file.take(*len), *len)
            }
        })
    }
}

impl ObsClient {
    pub fn new(ak: String, sk: String, bucket: String, endpoint: String) -> Self {
        let builder = Client::builder();
        // Tests only talk to local fixtures; machine proxy settings must not
        // route their requests elsewhere. Production still uses system proxies.
        #[cfg(test)]
        let builder = builder.no_proxy();
        let http = builder
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
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
            request_timeout: Duration::from_secs(120),
            transfer_timeout: Duration::from_secs(3600),
        }
    }

    pub fn with_timeouts(mut self, request_seconds: u64, transfer_seconds: u64) -> Self {
        self.request_timeout = Duration::from_secs(request_seconds);
        self.transfer_timeout = Duration::from_secs(transfer_seconds);
        self
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

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Build the signed request parts for one call.
    /// `query` is the full query string (already encoded) or empty.
    /// Returns (url, authorization, x-obs headers).
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
        let resource = canonical_resource(&self.bucket, key, query);
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
        self.send_with(
            method,
            key,
            query,
            body,
            content_type,
            extra_x_obs,
            extra_headers,
            Ok,
        )
    }

    /// One budget includes connection, HTTP status and response-body failures.
    #[allow(clippy::too_many_arguments)]
    fn send_with<T>(
        &self,
        method: &str,
        key: &str,
        query: &str,
        body: Option<RequestBody>,
        content_type: &str,
        extra_x_obs: &[(String, String)],
        extra_headers: &[(String, String)],
        finish: impl Fn(reqwest::blocking::Response) -> Result<T>,
    ) -> Result<T> {
        validate_metadata(extra_x_obs)?;
        let mut standard = extra_headers.to_vec();
        standard.extend(
            extra_x_obs
                .iter()
                .filter(|(k, _)| !k.starts_with("x-obs-"))
                .cloned(),
        );
        let content_type = extra_x_obs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or(content_type);
        standard.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
        let obs_headers: Vec<_> = extra_x_obs
            .iter()
            .filter(|(k, _)| k.starts_with("x-obs-"))
            .cloned()
            .collect();
        let content_md5 = body
            .as_ref()
            .map(RequestBody::md5)
            .transpose()?
            .unwrap_or_default();
        let transfer = matches!(&body, Some(RequestBody::File { .. }))
            || (method == "GET" && !key.is_empty() && query.is_empty())
            || (method == "POST" && query.starts_with("uploadId="))
            || obs_headers.iter().any(|(k, _)| k == "x-obs-copy-source");
        let timeout = if transfer {
            self.transfer_timeout
        } else {
            self.request_timeout
        };
        // Re-sign each attempt and back off with jitter after transient failures.
        let mut attempt = 0;
        loop {
            let (url, auth, x_obs) = self.sign(
                method,
                key,
                query,
                if body.is_some() { &content_md5 } else { "" },
                content_type,
                &obs_headers,
            );
            let mut req = self
                .http
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    &url,
                )
                .header("Authorization", &auth)
                .timeout(timeout);
            // No `Date` header: `x-obs-date` below carries it, and sending
            // both makes reqwest and OBS disagree about which one is
            // canonical.
            for (k, v) in &x_obs {
                req = req.header(k.as_str(), v.as_str());
            }
            for (k, v) in &standard {
                req = req.header(k.as_str(), v.as_str());
            }
            if !content_type.is_empty() {
                req = req.header("Content-Type", content_type);
            }
            if let Some(b) = &body {
                req = req.header("Content-MD5", &content_md5).body(b.body()?);
            }
            let result = match req.send() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if is_retryable_status(status) && attempt + 1 < RETRY_ATTEMPTS {
                        Err(ObsError::Http {
                            status,
                            method: method.into(),
                            path: key.into(),
                            body: response_diagnostic(resp),
                        })
                    } else {
                        finish(resp)
                    }
                }
                Err(e) => Err(ObsError::Network(e)),
            };
            match result {
                Ok(value) => return Ok(value),
                Err(e) => {
                    let retryable = match &e {
                        ObsError::Network(_) | ObsError::Incomplete(_) => true,
                        ObsError::Http { status, .. } => is_retryable_status(*status),
                        _ => false,
                    };
                    if !retryable || attempt + 1 == RETRY_ATTEMPTS {
                        return Err(e);
                    }
                }
            }
            std::thread::sleep(retry_delay(attempt));
            attempt += 1;
        }
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
            let body = response_diagnostic(resp);
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
            system_meta: SYSTEM_METADATA
                .iter()
                .filter_map(|name| {
                    Some((
                        name.to_string(),
                        headers.get(*name)?.to_str().ok()?.to_string(),
                    ))
                })
                .collect(),
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
            "prefix={}&max-keys={}",
            urlencoding::encode(prefix),
            max_keys
        );
        if !delimiter.is_empty() {
            query.push_str(&format!("&delimiter={}", urlencoding::encode(delimiter)));
        }
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
        Ok(self.list_all(prefix, "")?.keys)
    }

    /// Stored bytes reported by `GET /?storageinfo`, not bucket capacity.
    pub fn bucket_storage_size(&self) -> Result<Option<u64>> {
        let resp = self.send("GET", "", "storageinfo", None, "", &[], &[])?;
        let resp = Self::check(resp, "GET", "?storageinfo")?;
        let text = resp.text()?;
        Ok(parse_tag(&text, "Size").and_then(|v| v.parse().ok()))
    }

    /// Bucket storage quota: `GET /?quota`.
    ///
    /// `quota` is the configured byte limit. OBS reports 0 when no quota is
    /// set, which means "unlimited" rather than "no space" -- the opposite
    /// of what a `df` reader would assume, so callers must not treat 0 as
    /// "full".
    pub fn bucket_quota(&self) -> Result<Option<u64>> {
        let resp = self.send("GET", "", "quota", None, "", &[], &[])?;
        let resp = Self::check(resp, "GET", "?quota")?;
        let text = resp.text()?;
        Ok(parse_tag(&text, "StorageQuota").and_then(|v| v.parse().ok()))
    }

    /// List one directory level (delimiter="/"), following pagination.
    pub fn list_dir(&self, dir_prefix: &str) -> Result<ListResult> {
        self.list_all(dir_prefix, "/")
    }

    fn list_all(&self, prefix: &str, delimiter: &str) -> Result<ListResult> {
        let mut out = ListResult::default();
        let mut marker: Option<String> = None;
        loop {
            let page = self.list_objects(prefix, delimiter, marker.as_deref(), 1000)?;
            out.keys.extend(page.keys);
            out.prefixes.extend(page.prefixes);
            if !page.is_truncated {
                break;
            }
            if page.next_marker == marker {
                return Err(ObsError::Other("listing marker did not advance".into()));
            }
            marker = page.next_marker;
            if marker.is_none() {
                return Err(ObsError::Other(
                    "truncated listing has no continuation marker".into(),
                ));
            }
        }
        Ok(out)
    }

    #[cfg(test)]
    pub fn get_range(&self, key: &str, start: u64, len: usize) -> Result<Vec<u8>> {
        let meta = self
            .head_object(key)?
            .ok_or_else(|| ObsError::Other("object missing".into()))?;
        self.get_range_checked(
            key,
            start,
            len,
            meta.etag
                .as_deref()
                .ok_or_else(|| ObsError::Other("missing ETag".into()))?,
            meta.size,
        )
    }

    pub fn get_range_checked(
        &self,
        key: &str,
        start: u64,
        len: usize,
        etag: &str,
        total: u64,
    ) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = start
            .checked_add(len as u64 - 1)
            .filter(|end| *end < total)
            .ok_or_else(|| ObsError::Other("invalid range".into()))?;
        let headers = vec![
            ("Range".into(), format!("bytes={start}-{end}")),
            ("If-Match".into(), format!("\"{}\"", etag.trim_matches('"'))),
        ];
        self.send_with("GET", key, "", None, "", &[], &headers, |resp| {
            let resp = Self::check(resp, "GET", key)?;
            let expected = format!("bytes {start}-{end}/{total}");
            if resp.status().as_u16() != 206
                || resp
                    .headers()
                    .get("content-range")
                    .and_then(|v| v.to_str().ok())
                    != Some(expected.as_str())
            {
                return Err(ObsError::Other(format!(
                    "invalid Content-Range for {key}: expected {expected}"
                )));
            }
            let data = resp.bytes()?;
            if data.len() != len {
                return Err(ObsError::Incomplete(format!(
                    "range for {key}: expected {len}, received {}",
                    data.len()
                )));
            }
            Ok(data.to_vec())
        })
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

    /// Update metadata through OBS's dedicated API. Unspecified system
    /// headers survive REPLACE_NEW; the caller supplies all user metadata.
    pub fn set_object_meta(&self, key: &str, meta: &[(String, String)]) -> Result<()> {
        let mut headers = vec![("x-obs-metadata-directive".into(), "REPLACE_NEW".into())];
        headers.extend_from_slice(meta);
        Self::check(
            self.send("PUT", key, "metadata", None, "", &headers, &[])?,
            "PUT",
            key,
        )?;
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
        self.copy_object_with_limit(src_key, dst_key, MAX_SINGLE_SIZE)
    }

    fn copy_object_with_limit(&self, src_key: &str, dst_key: &str, limit: u64) -> Result<()> {
        let meta = self.head_object(src_key)?.ok_or_else(|| ObsError::Http {
            status: 404,
            method: "HEAD".into(),
            path: src_key.into(),
            body: "source missing".into(),
        })?;
        let etag = meta
            .etag
            .as_deref()
            .ok_or_else(|| ObsError::Other("copy source has no ETag".into()))?;
        let headers = vec![
            (
                "x-obs-copy-source".into(),
                format!("/{}/{}", self.bucket, encode_key(src_key)),
            ),
            ("x-obs-copy-source-if-match".into(), format!("\"{etag}\"")),
        ];
        if meta.size <= limit {
            let resp = self.send("PUT", dst_key, "", None, "", &headers, &[])?;
            checked_result(resp, "PUT", dst_key, "CopyObjectResult")?;
            return Ok(());
        }
        validate_object_size(meta.size)?;
        let mut metadata = meta.system_meta.clone();
        metadata.extend(
            meta.x_obs_meta
                .iter()
                .map(|(k, v)| (format!("x-obs-meta-{k}"), v.clone())),
        );
        let id = self.initiate_multipart_with_meta(dst_key, &metadata)?;
        let result = (|| {
            let part_size = limit.max(meta.size.div_ceil(10_000));
            let mut parts = Vec::new();
            for (index, start) in (0..meta.size).step_by(part_size as usize).enumerate() {
                let mut headers = headers.clone();
                headers.push((
                    "x-obs-copy-source-range".into(),
                    format!("bytes={start}-{}", (start + part_size).min(meta.size) - 1),
                ));
                let query = format!(
                    "partNumber={}&uploadId={}",
                    index + 1,
                    urlencoding::encode(&id)
                );
                let resp = self.send("PUT", dst_key, &query, None, "", &headers, &[])?;
                let etag = checked_result(resp, "PUT", dst_key, "CopyPartResult")?;
                parts.push((index as u32 + 1, etag));
            }
            self.complete_multipart(dst_key, &id, &parts)
        })();
        if result.is_err()
            && let Err(e) = self.abort_multipart(dst_key, &id)
        {
            tracing::error!(key=dst_key, upload_id=%id, error=%e, "failed to cancel multipart copy; source retained");
        }
        result
    }

    /// Multipart init with `x-obs-meta-*`; metadata set here ends up on the
    /// final object, which is the only chance to attach it for a large file.
    fn initiate_multipart_with_meta(&self, key: &str, meta: &[(String, String)]) -> Result<String> {
        let resp = self.send("POST", key, "uploads", None, "", meta, &[])?;
        let resp = Self::check(resp, "POST", key)?;
        let text = resp.text()?;
        parse_tag(&text, "UploadId")
            .ok_or_else(|| ObsError::Other("no UploadId in response".into()))
    }

    fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        body: RequestBody,
    ) -> Result<String> {
        let query = format!(
            "partNumber={part_number}&uploadId={}",
            urlencoding::encode(upload_id)
        );
        let resp = self.send(
            "PUT",
            key,
            &query,
            Some(body),
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
        if etag.is_empty() {
            return Err(ObsError::Other("upload part response has no ETag".into()));
        }
        Ok(etag)
    }

    fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[(u32, String)],
    ) -> Result<()> {
        let mut body = String::from("<CompleteMultipartUpload>");
        for (n, etag) in parts {
            let etag = quick_xml::escape::escape(etag);
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
        checked_result(resp, "POST", key, "CompleteMultipartUploadResult")?;
        Ok(())
    }

    fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        let query = format!("uploadId={}", urlencoding::encode(upload_id));
        let resp = self.send("DELETE", key, &query, None, "", &[], &[])?;
        if resp.status().as_u16() != 404 {
            Self::check(resp, "DELETE", key)?;
        }
        Ok(())
    }

    /// Download to a temporary file and publish it only after a complete GET.
    /// An unsuccessful or short response must never become writable staging.
    pub fn download_to(&self, key: &str, path: &Path, meta: &ObjectMeta) -> Result<()> {
        let partial = path.with_extension("download");
        let etag = meta
            .etag
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ObsError::Other("download requires ETag".into()))?;
        let headers = [("If-Match".into(), format!("\"{etag}\""))];
        let result = self.send_with("GET", key, "", None, "", &[], &headers, |response| {
            let mut response = Self::check(response, "GET", key)?;
            let mut file = File::create(&partial)?;
            let mut copied = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                // Separate network reads from local writes: only reads are retryable.
                let n = response
                    .read(&mut buffer)
                    .map_err(|e| ObsError::Incomplete(e.to_string()))?;
                if n == 0 {
                    break;
                }
                copied += n as u64;
                if copied > meta.size {
                    return Err(ObsError::Other(
                        "download exceeds expected object size".into(),
                    ));
                }
                file.write_all(&buffer[..n])?;
            }
            if copied != meta.size {
                return Err(ObsError::Incomplete(format!(
                    "expected {}, received {copied}",
                    meta.size
                )));
            }
            file.sync_all()?;
            std::fs::rename(&partial, path)?;
            Ok(())
        });
        if result.is_err() {
            let _ = std::fs::remove_file(&partial);
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
        tuning.validate()?;
        let len = File::open(path)?.metadata()?.len();
        validate_object_size(len)?;
        let journal_path = path.with_extension("upload.yaml");
        if journal_path.exists() {
            let previous: UploadJournal =
                serde_yaml::from_str(&std::fs::read_to_string(&journal_path)?)
                    .map_err(|e| ObsError::Other(format!("invalid upload recovery record: {e}")))?;
            if previous.bucket != self.bucket
                || previous.endpoint != self.endpoint
                || previous.key != key
            {
                return Err(ObsError::Other(
                    "upload recovery record belongs to another object; inspect before retry".into(),
                ));
            }
            self.abort_multipart(key, &previous.upload_id)?;
            std::fs::remove_file(&journal_path)?;
        }
        if len == 0 || (len < tuning.threshold && len <= MAX_SINGLE_SIZE) {
            let resp = self.send(
                "PUT",
                key,
                "",
                Some(RequestBody::File {
                    path: path.to_owned(),
                    offset: 0,
                    len,
                }),
                "application/octet-stream",
                meta,
                &[],
            )?;
            Self::check(resp, "PUT", key)?;
            return Ok(());
        }
        let part = multipart_part_size_with(len as usize, tuning.part_size) as u64;
        let id = self.initiate_multipart_with_meta(key, meta)?;
        let journal = Mutex::new(UploadJournal {
            endpoint: self.endpoint.clone(),
            bucket: self.bucket.clone(),
            key: key.into(),
            upload_id: id.clone(),
            size: len,
            parts: Vec::new(),
            completing: false,
        });
        if let Err(e) = write_journal(&journal_path, &journal.lock().unwrap()) {
            if let Err(abort) = self.abort_multipart(key, &id) {
                tracing::error!(key, upload_id=%id, error=%abort, "multipart cancellation failed");
            }
            return Err(e);
        }
        let next = AtomicU32::new(1);
        let failed = AtomicBool::new(false);
        let count = len.div_ceil(part) as u32;
        let result = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..tuning.concurrency.min(count as usize))
                .map(|_| {
                    scope.spawn(|| -> Result<()> {
                        while !failed.load(Ordering::Relaxed) {
                            let number = next.fetch_add(1, Ordering::Relaxed);
                            if number > count {
                                break;
                            }
                            let offset = (number as u64 - 1) * part;
                            let result = (|| {
                                let etag = self.upload_part(
                                    key,
                                    &id,
                                    number,
                                    RequestBody::File {
                                        path: path.to_owned(),
                                        offset,
                                        len: part.min(len - offset),
                                    },
                                )?;
                                let mut journal = journal.lock().unwrap();
                                journal.parts.push((number, etag));
                                write_journal(&journal_path, &journal)
                            })();
                            if result.is_err() {
                                failed.store(true, Ordering::Relaxed);
                            }
                            result?;
                        }
                        Ok(())
                    })
                })
                .collect();
            let mut error = None;
            for worker in workers {
                if let Err(e) = worker
                    .join()
                    .unwrap_or_else(|_| Err(ObsError::Other("upload worker panicked".into())))
                    && error.is_none()
                {
                    error = Some(e);
                }
            }
            error.map_or(Ok(()), Err)
        });
        if let Err(e) = result {
            match self.abort_multipart(key, &id) {
                Ok(()) => {
                    std::fs::remove_file(&journal_path)?;
                }
                Err(abort) => {
                    tracing::error!(key, upload_id=%id, error=%abort, "multipart cancellation failed; recovery record retained")
                }
            }
            return Err(e);
        }
        let mut journal = journal.into_inner().unwrap();
        journal.parts.sort_by_key(|(n, _)| *n);
        journal.completing = true;
        write_journal(&journal_path, &journal)?;
        // If completion is ambiguous, keep both the staged bytes and journal.
        self.complete_multipart(key, &id, &journal.parts)?;
        std::fs::remove_file(journal_path)?;
        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct UploadJournal {
    endpoint: String,
    bucket: String,
    key: String,
    upload_id: String,
    size: u64,
    parts: Vec<(u32, String)>,
    completing: bool,
}

fn write_journal(path: &Path, journal: &UploadJournal) -> Result<()> {
    crate::persist::write_yaml(path, journal).map_err(ObsError::from)
}

fn validate_object_size(len: u64) -> Result<()> {
    if len > MAX_OBJECT_SIZE {
        return Err(ObsError::Io(std::io::Error::from_raw_os_error(libc::EFBIG)));
    }
    Ok(())
}

fn response_diagnostic(response: reqwest::blocking::Response) -> String {
    let request = response
        .headers()
        .get("x-obs-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let extended = response
        .headers()
        .get("x-obs-id-2")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    format!(
        "request-id={request}, id-2={extended}: {}",
        response
            .text()
            .unwrap_or_else(|e| format!("unreadable error body: {e}"))
    )
}

fn checked_result(
    response: reqwest::blocking::Response,
    method: &str,
    key: &str,
    expected: &str,
) -> Result<String> {
    let response = ObsClient::check(response, method, key)?;
    let request = response
        .headers()
        .get("x-obs-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let text = response.text()?;
    let mut reader = Reader::from_str(&text);
    let mut depth = 0usize;
    let mut root = None;
    let mut closed = false;
    let mut direct_etag = 0;
    let mut in_etag = false;
    let mut etag = String::new();
    loop {
        match reader.read_event()? {
            Event::Start(e) => {
                if in_etag {
                    return Err(ObsError::Other("nested element in ETag".into()));
                }
                if depth == 0 {
                    if root.is_some() {
                        return Err(ObsError::Other("multiple response roots".into()));
                    }
                    root = Some(e.local_name().as_ref().to_string());
                }
                if e.local_name().as_ref() == "ETag" {
                    if depth != 1 {
                        return Err(ObsError::Other("invalid nested ETag".into()));
                    }
                    direct_etag += 1;
                    in_etag = true;
                }
                depth += 1;
            }
            Event::Empty(_) if depth == 0 => {
                return Err(ObsError::Other("unexpected empty response root".into()));
            }
            Event::Empty(e) if in_etag || e.local_name().as_ref() == "ETag" => {
                return Err(ObsError::Other(
                    "invalid empty element in ETag result".into(),
                ));
            }
            Event::DocType(_) => {
                return Err(ObsError::Other("unexpected XML document type".into()));
            }
            Event::Text(e) if depth == 0 && !e.as_ref().trim().is_empty() => {
                return Err(ObsError::Other("text outside response root".into()));
            }
            Event::Text(e) if in_etag => etag.push_str(&e.xml10_content()),
            Event::CData(e) if in_etag => etag.push_str(&e.xml10_content()),
            Event::GeneralRef(e) if in_etag => match e.resolve_char_ref() {
                Ok(Some(ch)) => etag.push(ch),
                _ => etag.push_str(
                    quick_xml::escape::resolve_predefined_entity(e.as_ref())
                        .ok_or_else(|| ObsError::Other("unknown XML entity in ETag".into()))?,
                ),
            },
            Event::End(e) => {
                if e.local_name().as_ref() == "ETag" {
                    in_etag = false;
                }
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| ObsError::Other("invalid response XML".into()))?;
                if depth == 0 {
                    closed = true;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let etag = etag.trim().trim_matches('"');
    if root.as_deref() != Some(expected)
        || !closed
        || depth != 0
        || etag.trim().is_empty()
        || direct_etag != 1
    {
        return Err(ObsError::Other(format!(
            "{method} {key}: invalid {expected}, request-id={request}: {text}"
        )));
    }
    Ok(etag.to_string())
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
fn parse_list_xml(xml: &str) -> Result<ListResult> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut out = ListResult::default();
    // Stack of element names; Contents/CommonPrefixes are tracked by depth.
    let mut stack: Vec<String> = Vec::new();
    let mut cur_key: Option<String> = None;
    let mut cur_text_elem: Option<String> = None;
    let mut cur_text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_owned();
                if name == "Contents" {
                    cur_key = None;
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
                    out.keys.push(key);
                }
                // Commit the element's text now that all fragments are in.
                if let Some(elem) = cur_text_elem.take() {
                    let in_contents = stack.iter().any(|s| s == "Contents");
                    let in_prefix = stack.iter().any(|s| s == "CommonPrefixes");
                    match elem.as_str() {
                        "Key" if in_contents => cur_key = Some(std::mem::take(&mut cur_text)),
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
        && let Some(last) = out.keys.last()
    {
        out.next_marker = Some(last.clone());
    }
    Ok(out)
}

/// Sign the encoded path exactly as sent, plus sorted OBS subresources.
fn canonical_resource(bucket: &str, key: &str, query: &str) -> String {
    let mut resource = format!("/{bucket}/{}", encode_key(key));
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

/// Grow the configured part size enough to stay within the 10000-part limit.
fn multipart_part_size_with(file_len: usize, base: usize) -> usize {
    const MAX_PARTS: usize = 10_000;
    let base = base.max(MIN_PART_SIZE); // OBS permits 100 KiB for non-final parts
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
    pub concurrency: usize,
}

impl UploadTuning {
    pub fn validate(self) -> Result<()> {
        if self.threshold == 0
            || !(MIN_PART_SIZE..=MAX_SINGLE_SIZE as usize).contains(&self.part_size)
            || !(1..=32).contains(&self.concurrency)
        {
            return Err(ObsError::Other("invalid upload settings: threshold > 0, part size 100 KiB..5 GiB, concurrency 1..32 required".into()));
        }
        Ok(())
    }
}

impl Default for UploadTuning {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_MULTIPART_THRESHOLD,
            part_size: DEFAULT_PART_SIZE,
            concurrency: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfer_errors_share_one_request_budget() {
        // Two HTTP failures, one short body, then two more HTTP failures.
        // A second body-retry budget would incorrectly allow a sixth GET.
        std::thread::scope(|scope| {
            for range in [true, false] {
                scope.spawn(move || {
                    let faults = serde_json::json!([
                        {"method":"GET","key":"data","status":503,"count":2},
                        {"method":"GET","key":"data","status":if range {206} else {200},
                         "body":"x","headers":{"Content-Range":"bytes 0-3/4"}},
                        {"method":"GET","key":"data","status":503,"count":2}
                    ]);
                    let mock = crate::test_support::MockObs::new(&faults.to_string());
                    let client = mock.client();
                    client.put_object_with_meta("data", b"data", &[]).unwrap();
                    let meta = client.head_object("data").unwrap().unwrap();
                    let destination = mock.staging.join("downloaded");
                    if range {
                        assert!(
                            client
                                .get_range_checked("data", 0, 4, meta.etag.as_deref().unwrap(), 4)
                                .is_err()
                        );
                    } else {
                        assert!(client.download_to("data", &destination, &meta).is_err());
                        assert!(!destination.exists());
                        assert!(!destination.with_extension("download").exists());
                    }
                    assert_eq!(mock.stats().requests["GET data"], RETRY_ATTEMPTS as usize);
                });
            }
        });
    }

    #[test]
    fn copy_requires_a_complete_success_result() {
        for body in [
            "<Error><Code>InternalError</Code></Error>",
            "",
            "<CopyObjectResult><ETag>abc</ETag>",
            "<CopyObjectResult><ETag/></CopyObjectResult>",
            "<CopyObjectResult><ETag>a<X/>b</ETag></CopyObjectResult>",
            "<CopyObjectResult><ETag>a</ETag><ETag>b</ETag></CopyObjectResult>",
            "<CopyObjectResult><ETag>a</ETag></CopyObjectResult><Other/>",
        ] {
            let faults =
                serde_json::json!([{"method":"PUT","key":"target","status":200,"body":body}]);
            let mock = crate::test_support::MockObs::new(&faults.to_string());
            let client = mock.client();
            client
                .put_object_with_meta("source", b"irreplaceable", &[])
                .unwrap();
            assert!(
                client.copy_object("source", "target").is_err(),
                "accepted {body}"
            );
            assert!(client.head_object("source").unwrap().is_some());
            assert!(client.head_object("target").unwrap().is_none());
        }
    }

    #[test]
    fn copy_result_accepts_namespace_and_decodes_etag_in_one_pass() {
        let mock = crate::test_support::MockObs::new(
            r#"[{"method":"PUT","key":"target","status":200,"body":"<?xml version=\"1.0\"?><r:CopyObjectResult xmlns:r=\"urn:obs\"><r:ETag>&quot;a&amp;b&#49;<![CDATA[c]]>&quot;</r:ETag></r:CopyObjectResult>"}]"#,
        );
        let client = mock.client();
        let response = client
            .send("PUT", "target", "", None, "", &[], &[])
            .unwrap();
        assert_eq!(
            checked_result(response, "PUT", "target", "CopyObjectResult").unwrap(),
            "a&b1c"
        );
    }

    #[test]
    fn metadata_update_and_multipart_copy_preserve_content_and_system_headers() {
        let mock = crate::test_support::MockObs::new("[]");
        let client = mock.client();
        client
            .put_object_with_meta(
                "src",
                b"abcdefghijk",
                &[
                    ("content-type".into(), "text/plain".into()),
                    ("cache-control".into(), "max-age=3600".into()),
                    ("x-obs-meta-owner".into(), "alice".into()),
                ],
            )
            .unwrap();
        client
            .set_object_meta("src", &[("x-obs-meta-owner".into(), "bob".into())])
            .unwrap();
        let meta = client.head_object("src").unwrap().unwrap();
        assert!(
            meta.system_meta
                .contains(&("content-type".into(), "text/plain".into()))
        );
        assert!(
            meta.system_meta
                .contains(&("cache-control".into(), "max-age=3600".into()))
        );
        client.copy_object_with_limit("src", "dst", 4).unwrap();
        assert_eq!(client.get_range("dst", 0, 11).unwrap(), b"abcdefghijk");
        let copied = client.head_object("dst").unwrap().unwrap();
        assert_eq!(copied.system_meta, meta.system_meta);
        assert_eq!(copied.x_obs_meta, meta.x_obs_meta);
        assert_eq!(mock.stats().uploads, 0);
        assert_eq!(mock.stats().signature_failures, 0);
    }

    #[test]
    fn completion_errors_and_cancel_errors_are_not_success() {
        let mock = crate::test_support::MockObs::new(
            r#"[
            {"method":"POST","query":"uploadId","key":"data","status":200,"body":"<Error><Code>InternalError</Code></Error>"},
            {"method":"DELETE","query":"uploadId","key":"data","status":403}
        ]"#,
        );
        let client = mock.client();
        let id = client.initiate_multipart_with_meta("data", &[]).unwrap();
        let etag = client
            .upload_part("data", &id, 1, RequestBody::Bytes(b"last part".to_vec()))
            .unwrap();
        assert!(
            client
                .complete_multipart("data", &id, &[(1, etag)])
                .is_err()
        );
        assert!(client.abort_multipart("data", &id).is_err());
        assert_eq!(mock.stats().uploads, 1);
        client.abort_multipart("data", &id).unwrap();
        assert_eq!(mock.stats().uploads, 0);
    }

    #[test]
    fn failed_cancel_retains_journal_and_retry_cleans_recorded_upload() {
        let mock = crate::test_support::MockObs::new(
            r#"[
            {"method":"PUT","query":"partNumber","key":"backup","status":403},
            {"method":"DELETE","query":"uploadId","key":"backup","status":403}
        ]"#,
        );
        let source = mock.staging.join("input");
        std::fs::write(&source, b"local backup").unwrap();
        let client = mock.client();
        let tuning = UploadTuning {
            threshold: 1,
            ..Default::default()
        };
        assert!(
            client
                .upload_file_with_meta("backup", &source, tuning, &[])
                .is_err()
        );
        let record = source.with_extension("upload.yaml");
        let journal: UploadJournal =
            serde_yaml::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
        assert!(!journal.upload_id.is_empty());
        assert_eq!(journal.key, "backup");
        assert_eq!(mock.stats().uploads, 1);
        client
            .upload_file_with_meta("backup", &source, tuning, &[])
            .unwrap();
        assert!(!record.exists());
        assert_eq!(mock.stats().uploads, 0);
        assert_eq!(client.get_range("backup", 0, 12).unwrap(), b"local backup");
    }

    #[test]
    fn uncertain_completion_keeps_recovery_record_and_local_data() {
        let mock = crate::test_support::MockObs::new(
            r#"[{"method":"POST","query":"uploadId","key":"data","status":200,"body":"<CompleteMultipartUploadResult>"}]"#,
        );
        let client = mock.client();
        let file = mock.staging.join("data");
        std::fs::write(&file, b"recover me").unwrap();
        let tuning = UploadTuning {
            threshold: 1,
            ..Default::default()
        };
        assert!(
            client
                .upload_file_with_meta("data", &file, tuning, &[])
                .is_err()
        );
        let journal = file.with_extension("upload.yaml");
        let record: UploadJournal =
            serde_yaml::from_str(&std::fs::read_to_string(&journal).unwrap()).unwrap();
        assert!(record.completing);
        assert_eq!(record.parts.len(), 1);
        assert_eq!(std::fs::read(&file).unwrap(), b"recover me");
        client
            .upload_file_with_meta("data", &file, tuning, &[])
            .unwrap();
        assert_eq!(client.get_range("data", 0, 10).unwrap(), b"recover me");
        assert!(!journal.exists());
        assert_eq!(mock.stats().uploads, 0);
    }

    #[test]
    fn range_requests_pin_version_and_validate_response_interval() {
        let mock = crate::test_support::MockObs::new("[]");
        let client = mock.client();
        client.put_object_with_meta("data", b"AAAA", &[]).unwrap();
        let meta = client.head_object("data").unwrap().unwrap();
        client.put_object_with_meta("data", b"BBBB", &[]).unwrap();
        assert!(matches!(
            client.get_range_checked("data", 0, 4, meta.etag.as_deref().unwrap(), 4),
            Err(ObsError::Http { status: 412, .. })
        ));
        for (status, range) in [(200, "bytes 0-3/4"), (206, "bytes 1-4/5")] {
            let faults = serde_json::json!([{"method":"GET","key":"data","status":status,"body":"abcd","headers":{"Content-Range":range}}]);
            let mock = crate::test_support::MockObs::new(&faults.to_string());
            assert!(
                mock.client()
                    .get_range_checked("data", 0, 4, "tag", 4)
                    .is_err()
            );
        }
    }

    #[test]
    fn obs_limits_are_checked_before_network_requests() {
        assert!(
            UploadTuning {
                part_size: MIN_PART_SIZE,
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
        assert!(
            UploadTuning {
                part_size: MIN_PART_SIZE - 1,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            UploadTuning {
                part_size: MAX_SINGLE_SIZE as usize + 1,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(validate_object_size(MAX_OBJECT_SIZE).is_ok());
        assert!(validate_object_size(MAX_OBJECT_SIZE + 1).is_err());
        assert!(
            validate_metadata(&[("x-obs-meta-k".into(), "v".repeat(MAX_METADATA_SIZE))]).is_err()
        );
    }

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
            assert_eq!(
                mock.stats().signature_failures,
                0,
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
                listed.keys.iter().any(|k| k == key),
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
        assert_eq!(r.keys, ["backups/a.tar.gz"]);
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
            MIN_PART_SIZE
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
        assert_eq!(r.keys, ["a&b/中文.txt"]);
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
                        concurrency: 4,
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
                    concurrency: 4,
                },
                &[],
            )
            .unwrap();
        assert_eq!(client.head_object("empty").unwrap().unwrap().size, 0);
        assert_eq!(mock.stats().signature_failures, 0);
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
        assert_eq!(mock.stats().uploads, 0);
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
