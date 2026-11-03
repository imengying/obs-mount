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
use std::time::Duration;
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;

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

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ObjectMeta {
    pub size: u64,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ListEntry {
    pub key: String,
    pub size: u64,
    pub is_dir_placeholder: bool,
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
    endpoint: String, // e.g. https://obs.cn-north-4.myhuaweicloud.com (no trailing /)
    http: Client,
}

impl ObsClient {
    pub fn new(ak: String, sk: String, bucket: String, endpoint: String) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("reqwest client");
        Self {
            ak,
            sk,
            bucket,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            http,
        }
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
    ) -> (String, String, String, Vec<(String, String)>) {
        let date = rfc1123_now();
        let mut x_obs: Vec<(String, String)> = vec![("x-obs-date".to_string(), date.clone())];
        for (k, v) in extra_x_obs {
            x_obs.push((k.clone(), v.clone()));
        }
        // CanonicalizedResource: /<bucket>/<key>[?<sorted sub-resources>]
        let mut resource = format!("/{}/{}", self.bucket, key);
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
            &date,
            &x_obs,
            &resource,
        );
        let auth = format!("OBS {}:{}", self.ak, sig);
        let url = if query.is_empty() {
            format!("{}/{}", self.endpoint, encode_key(key))
        } else {
            format!("{}/{}?{}", self.endpoint, encode_key(key), query)
        };
        // When endpoint already contains the bucket as virtual host, the
        // object URL is <endpoint>/<key>. When a custom endpoint without a
        // bucket host is used, callers pass OBS_ENDPOINT including the bucket
        // host (documented in README); the resource string above still uses
        // /<bucket>/<key> as the API requires.
        (url, auth, date, x_obs)
    }

    // One call = one signed request; grouping these fields into a struct
    // would only move them one level down without making the call clearer.
    #[allow(clippy::too_many_arguments)]
    fn send(
        &self,
        method: &str,
        key: &str,
        query: &str,
        body: Option<Vec<u8>>,
        content_type: &str,
        extra_x_obs: &[(String, String)],
        extra_headers: &[(String, String)],
    ) -> Result<reqwest::blocking::Response> {
        let content_md5 = body.as_ref().map(|b| md5_base64(b)).unwrap_or_default();
        // Only send Content-MD5 when there is a body; otherwise the signed
        // value must stay empty or the signature will not match.
        let (url, auth, date, x_obs) = self.sign(
            method,
            key,
            query,
            if body.is_some() { &content_md5 } else { "" },
            content_type,
            extra_x_obs,
        );
        let mut last_err: Option<ObsError> = None;
        for attempt in 0..4 {
            let mut req = self
                .http
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    &url,
                )
                .header("Authorization", &auth)
                .header("Date", &date);
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
                req = req.header("Content-MD5", &content_md5).body(b.clone());
            }
            match req.send() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 403 || !(500..600).contains(&status) {
                        return Ok(resp);
                    }
                    // 5xx: retry with backoff, unless this was the last try.
                    if attempt == 3 {
                        return Ok(resp);
                    }
                    let body_text = resp.text().unwrap_or_default();
                    last_err = Some(ObsError::Http {
                        status,
                        method: method.to_string(),
                        path: key.to_string(),
                        body: body_text,
                    });
                    std::thread::sleep(Duration::from_millis(500 * (attempt as u64 + 1)));
                }
                Err(e) => {
                    if attempt == 3 {
                        return Err(ObsError::Network(e));
                    }
                    last_err = Some(ObsError::Network(e));
                    std::thread::sleep(Duration::from_millis(500 * (attempt as u64 + 1)));
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

    pub fn put_object(&self, key: &str, data: &[u8]) -> Result<()> {
        let resp = self.send(
            "PUT",
            key,
            "",
            Some(data.to_vec()),
            "application/octet-stream",
            &[],
            &[],
        )?;
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

    pub fn initiate_multipart(&self, key: &str) -> Result<String> {
        let resp = self.send("POST", key, "uploads", None, "", &[], &[])?;
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
            Some(data.to_vec()),
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
            Some(body.into_bytes()),
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

    /// Upload, choosing single PUT below `multipart_threshold` (and always
    /// for empty files, which have no parts to complete) and multipart
    /// above it. Parts are uploaded in parallel (4 at a time, one blocking
    /// thread per part; no new dependency) instead of one after another, so
    /// a large backup is bound by bandwidth, not by per-part round-trips.
    /// Parts are sorted by part number before Complete, and on any failure
    /// every in-flight part is still joined before abort, so abort cannot
    /// race an unfinished part upload. The part size is 8 MiB by default
    /// (AWS CLI/boto3 chunk size) but grows when the file would otherwise
    /// need more than 10000 parts (the multipart limit) — same adaptation
    /// OpenList's S3 driver relies on via the AWS SDK — so a file above
    /// ~80 GiB does not fail at CompleteMultipartUpload.
    pub fn upload_file(&self, key: &str, data: &[u8], multipart_threshold: u64) -> Result<()> {
        if data.is_empty() || (data.len() as u64) < multipart_threshold {
            return self.put_object(key, data);
        }
        let upload_id = self.initiate_multipart(key)?;
        let part: usize = multipart_part_size(data.len());
        const CONCURRENCY: usize = 4;
        let mut parts: Vec<(u32, String)> = Vec::new();
        let mut result: Result<()> = Ok(());
        // Join one batch of in-flight parts before starting the next, so
        // at most CONCURRENCY requests (and part * CONCURRENCY bytes of
        // copied chunk data) are live at once.
        let mut handles: Vec<(u32, std::thread::JoinHandle<Result<String>>)> = Vec::new();
        for (idx, chunk) in data.chunks(part).enumerate() {
            // OBS numbers parts from 1.
            let part_no = idx as u32 + 1;
            let client = self.clone();
            let key = key.to_owned();
            let upload_id = upload_id.clone();
            let chunk = chunk.to_vec();
            handles.push((
                part_no,
                std::thread::spawn(move || client.upload_part(&key, &upload_id, part_no, &chunk)),
            ));
            if handles.len() == CONCURRENCY {
                // Join the whole batch even after a failure, so abort
                // below cannot race an in-flight part upload.
                for (n, h) in handles.drain(..) {
                    match h.join() {
                        Ok(Ok(etag)) => {
                            if result.is_ok() {
                                parts.push((n, etag));
                            }
                        }
                        Ok(Err(e)) => {
                            if result.is_ok() {
                                result = Err(e);
                            }
                        }
                        Err(_) => {
                            if result.is_ok() {
                                result = Err(ObsError::Other("part upload thread panicked".into()));
                            }
                        }
                    }
                }
                if result.is_err() {
                    break;
                }
            }
        }
        // Drain the tail batch too, joining every handle even after a
        // failure: breaking early here used to drop unjoined handles, so
        // abort below could race a still-running part upload.
        for (n, h) in handles.drain(..) {
            match h.join() {
                Ok(Ok(etag)) => {
                    if result.is_ok() {
                        parts.push((n, etag));
                    }
                }
                Ok(Err(e)) => {
                    if result.is_ok() {
                        result = Err(e);
                    }
                }
                Err(_) => {
                    if result.is_ok() {
                        result = Err(ObsError::Other("part upload thread panicked".into()));
                    }
                }
            }
        }
        if result.is_ok() {
            parts.sort_by_key(|(n, _)| *n);
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

/// Part size for a multipart upload: 8 MiB normally, growing just enough
/// that the file never needs more than 10000 parts.
pub fn multipart_part_size(file_len: usize) -> usize {
    const BASE_PART: usize = 8 * 1024 * 1024;
    const MAX_PARTS: usize = 10_000;
    BASE_PART.max(file_len.div_ceil(MAX_PARTS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_size_stays_8mib_below_limit_and_grows_above() {
        assert_eq!(multipart_part_size(8 * 1024 * 1024), 8 * 1024 * 1024);
        // 100 GiB would need 12800 parts at 8 MiB; grown size keeps it at 10000.
        let grown = multipart_part_size(100 * 1024 * 1024 * 1024);
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
}
