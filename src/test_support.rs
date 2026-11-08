//! Shared in-process fixtures, compiled only for the crate's unit tests.
//! Authentication is implemented independently of the production OBS client.
use crate::obs::ObsClient;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Cursor};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tiny_http::{Header, Request, Response, Server, StatusCode};

const BUCKET: &str = "test-bucket";
const AK: &str = "TESTAK";
const SK: &str = "TESTSK";
const XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
const SUBRESOURCES: &[&str] = &[
    "acl",
    "cors",
    "lifecycle",
    "location",
    "policy",
    "tagging",
    "versioning",
    "uploads",
    "uploadId",
    "partNumber",
    "delete",
    "website",
    "storagePolicy",
    "quota",
    "storageinfo",
    "encryption",
    "metadata",
    "versionId",
    "response-content-type",
    "response-content-language",
    "response-expires",
    "response-cache-control",
    "response-content-disposition",
    "response-content-encoding",
];

#[derive(Default)]
pub struct Config {
    pub faults: Vec<Fault>,
    pub quota: u64,
    pub file_bucket: bool,
}

#[derive(Deserialize)]
pub struct Fault {
    method: String,
    key: String,
    query: Option<String>,
    status: u16,
    #[serde(default)]
    body: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default = "one")]
    count: usize,
    #[serde(default)]
    delay_ms: u64,
}

fn one() -> usize {
    1
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Stats {
    pub signature_failures: usize,
    pub objects: usize,
    pub uploads: usize,
    pub requests: BTreeMap<String, usize>,
}

#[derive(Clone)]
struct Object {
    data: Vec<u8>,
    meta: BTreeMap<String, String>,
    modified: String,
    etag: String,
}

impl Object {
    fn new(data: Vec<u8>, meta: BTreeMap<String, String>) -> Self {
        let etag = format!("\"{}\"", md5_hex(&data));
        Self {
            data,
            meta,
            etag,
            modified: chrono::Utc::now()
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string(),
        }
    }

    fn etag(&self) -> String {
        self.etag.clone()
    }
}

struct Upload {
    key: String,
    parts: BTreeMap<u32, Vec<u8>>,
    meta: BTreeMap<String, String>,
}

#[derive(Default)]
struct State {
    objects: BTreeMap<String, Object>,
    uploads: HashMap<String, Upload>,
    sequence: u64,
    signature_failures: usize,
    config: Config,
    requests: BTreeMap<String, usize>,
}

impl State {
    fn stats(&self) -> Stats {
        Stats {
            signature_failures: self.signature_failures,
            objects: self.objects.len(),
            uploads: self.uploads.len(),
            requests: self.requests.clone(),
        }
    }
}

pub struct MockServer {
    pub endpoint: String,
    stopping: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl MockServer {
    pub fn start(config: Config) -> io::Result<Self> {
        let server = Arc::new(Server::http(("127.0.0.1", 0)).map_err(io::Error::other)?);
        let endpoint = format!("http://{}", server.server_addr());
        let state = Arc::new(Mutex::new(State {
            config,
            ..State::default()
        }));
        let stopping = Arc::new(AtomicBool::new(false));
        let workers = (0..4)
            .map(|_| {
                let server = server.clone();
                let state = state.clone();
                let stopping = stopping.clone();
                thread::spawn(move || {
                    while !stopping.load(Ordering::Acquire) {
                        match server.recv_timeout(Duration::from_millis(50)) {
                            Ok(Some(request)) => serve(request, &state),
                            Ok(None) => {}
                            Err(_) => break,
                        }
                    }
                })
            })
            .collect();
        Ok(Self {
            endpoint,
            stopping,
            workers,
        })
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            worker.join().expect("mock OBS worker panicked");
        }
    }
}

struct Incoming {
    method: String,
    url: String,
    raw_path: String,
    raw_query: String,
    key: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Incoming {
    fn read(request: &mut Request) -> io::Result<Self> {
        let url = request.url().to_string();
        let (raw_path, raw_query) = url.split_once('?').unwrap_or((&url, ""));
        let key = decode(strip_bucket(raw_path));
        let query = raw_query
            .split('&')
            .filter(|part| !part.is_empty())
            .map(|part| {
                let (name, value) = part.split_once('=').unwrap_or((part, ""));
                // '+' is a literal plus in OBS query parameters, not a space.
                (decode(name), decode(value))
            })
            .collect();
        let mut body = Vec::new();
        request.as_reader().read_to_end(&mut body)?;
        Ok(Self {
            method: request.method().as_str().to_string(),
            raw_path: raw_path.to_string(),
            raw_query: raw_query.to_string(),
            key,
            query,
            headers: request
                .headers()
                .iter()
                .map(|h| {
                    (
                        h.field.to_string().to_ascii_lowercase(),
                        h.value.to_string(),
                    )
                })
                .collect(),
            url,
            body,
        })
    }

    fn header(&self, name: &str) -> &str {
        self.headers.get(name).map(String::as_str).unwrap_or("")
    }

    fn meta(&self) -> BTreeMap<String, String> {
        self.headers
            .iter()
            .filter(|(k, _)| {
                k.starts_with("x-obs-meta-")
                    || matches!(
                        k.as_str(),
                        "content-type"
                            | "content-encoding"
                            | "content-disposition"
                            | "content-language"
                            | "cache-control"
                            | "expires"
                            | "x-obs-storage-class"
                    )
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn valid_auth(&self) -> bool {
        if let Some(md5) = self.headers.get("content-md5")
            && *md5 != B64.encode(Md5::digest(&self.body))
        {
            return false;
        }
        let Some((scheme, credentials)) = self.header("authorization").split_once(' ') else {
            return false;
        };
        // AWS/SigV2 is retained for comparison runs with Huawei's obsfs.
        let prefix = match scheme {
            "OBS" => "x-obs-",
            "AWS" => "x-amz-",
            _ => return false,
        };
        let Some((ak, signature)) = credentials.split_once(':') else {
            return false;
        };
        if ak != AK {
            return false;
        }
        let date = if self.header("x-obs-date").is_empty() {
            self.header("date")
        } else {
            ""
        };
        let mut canonical = format!(
            "{}\n{}\n{}\n{}\n",
            self.method,
            self.header("content-md5"),
            self.header("content-type"),
            date
        );
        for (name, value) in &self.headers {
            if name.starts_with(prefix) {
                canonical.push_str(&format!("{name}:{}\n", value.trim()));
            }
        }
        // Sign the encoded wire path, including percent escapes for CJK/spaces.
        canonical.push_str(&format!("/{BUCKET}/{}", strip_bucket(&self.raw_path)));
        let mut subresources: Vec<_> = self
            .raw_query
            .split('&')
            .filter(|part| SUBRESOURCES.contains(&part.split('=').next().unwrap_or("")))
            .collect();
        subresources.sort_unstable();
        if !subresources.is_empty() {
            canonical.push('?');
            canonical.push_str(&subresources.join("&"));
        }
        let Ok(signature) = B64.decode(signature) else {
            return false;
        };
        let mut mac = Hmac::<Sha1>::new_from_slice(SK.as_bytes()).unwrap();
        mac.update(canonical.as_bytes());
        mac.verify_slice(&signature).is_ok()
    }
}

fn strip_bucket(path: &str) -> &str {
    let path = path.trim_start_matches('/');
    if path == BUCKET {
        ""
    } else {
        path.strip_prefix("test-bucket/").unwrap_or(path)
    }
}

fn decode(value: &str) -> String {
    urlencoding::decode(value).unwrap().into_owned()
}

fn md5_hex(data: &[u8]) -> String {
    Md5::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    length: Option<usize>,
    delay_ms: u64,
}

impl Reply {
    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            length: None,
            delay_ms: 0,
        }
    }
    fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }
    fn xml(status: u16, xml: String) -> Self {
        Self {
            body: format!("{XML}{xml}").into_bytes(),
            ..Self::empty(status)
        }
        .header("Content-Type", "application/xml")
    }
    fn error(status: u16, code: &str) -> Self {
        Self::xml(status, format!("<Error><Code>{code}</Code></Error>"))
    }
}

fn serve(mut request: Request, state: &Mutex<State>) {
    let reply = match Incoming::read(&mut request) {
        Ok(incoming) => {
            let mut state = state.lock().unwrap();
            state.handle(&incoming)
        }
        Err(_) => Reply::error(400, "BadRequest"),
    };
    // Delay only this response; unrelated mock requests must still progress.
    thread::sleep(Duration::from_millis(reply.delay_ms));
    let headers = reply
        .headers
        .into_iter()
        .map(|(k, v)| Header::from_bytes(k, v).unwrap())
        .collect();
    let length = reply.length.unwrap_or(reply.body.len());
    // tiny_http handles chunked request bodies, HEAD suppression and keep-alive.
    let response = Response::new(
        StatusCode(reply.status),
        headers,
        Cursor::new(reply.body),
        Some(length),
        None,
    )
    .with_chunked_threshold(usize::MAX);
    let _ = request.respond(response);
}

impl State {
    fn handle(&mut self, req: &Incoming) -> Reply {
        if req.method == "GET" && req.url == "/__stats" {
            return Reply {
                body: serde_json::to_vec_pretty(&self.stats()).unwrap(),
                ..Reply::empty(200)
            }
            .header("Content-Type", "application/json");
        }
        *self
            .requests
            .entry(format!("{} {}", req.method, req.key))
            .or_default() += 1;
        for fault in &mut self.config.faults {
            if fault.count > 0
                && fault.method == req.method
                && fault.key == req.key
                && fault
                    .query
                    .as_ref()
                    .is_none_or(|q| req.query.contains_key(q))
            {
                fault.count -= 1;
                return Reply {
                    status: fault.status,
                    body: fault.body.as_bytes().to_vec(),
                    headers: fault.headers.clone().into_iter().collect(),
                    length: None,
                    delay_ms: fault.delay_ms,
                };
            }
        }
        if !req.valid_auth() {
            self.signature_failures += 1;
            return Reply::error(403, "SignatureDoesNotMatch");
        }
        match req.method.as_str() {
            "HEAD" | "GET" => self.get(req),
            "PUT" => self.put(req),
            "POST" => self.post(req),
            "DELETE" => {
                if let Some(id) = req.query.get("uploadId") {
                    self.uploads.remove(id);
                } else if self.objects.remove(&req.key).is_none() {
                    return Reply::error(404, "NoSuchKey");
                }
                Reply::empty(204)
            }
            _ => Reply::error(405, "MethodNotAllowed"),
        }
    }

    fn get(&self, req: &Incoming) -> Reply {
        if req.key.is_empty() {
            if req.method == "HEAD" {
                return if self.config.file_bucket {
                    Reply::empty(200)
                        .header("x-obs-bucket-type", "POSIX")
                        .header("x-obs-fs-file-interface", "Enabled")
                } else {
                    Reply::empty(200)
                };
            }
            if req.query.contains_key("quota") {
                return Reply::xml(
                    200,
                    format!(
                        "<Quota><StorageQuota>{}</StorageQuota></Quota>",
                        self.config.quota
                    ),
                );
            }
            if req.query.contains_key("storageinfo") {
                let size: usize = self.objects.values().map(|o| o.data.len()).sum();
                return Reply::xml(
                    200,
                    format!(
                        "<GetBucketStorageInfoResult><Location>cn-north-4</Location><Bucket>{BUCKET}</Bucket><Size>{size}</Size><ObjectNumber>{}</ObjectNumber></GetBucketStorageInfoResult>",
                        self.objects.len()
                    ),
                );
            }
            return self.list(req);
        }
        let Some(object) = self.objects.get(&req.key) else {
            return Reply::error(404, "NoSuchKey");
        };
        let mut reply = Reply::empty(200)
            .header("ETag", object.etag())
            .header("Last-Modified", object.modified.clone());
        if req.method == "HEAD" {
            reply.length = Some(object.data.len());
            reply.headers.extend(object.meta.clone());
            return reply;
        }
        if let Some(tag) = req.headers.get("if-match")
            && *tag != object.etag()
        {
            return Reply::empty(412);
        }
        reply = reply.header("Content-Type", "application/octet-stream");
        if let Some(range) = req.header("range").strip_prefix("bytes=") {
            let Some((start, end)) = range.split_once('-') else {
                return Reply::empty(416);
            };
            let Ok(start) = start.parse::<usize>() else {
                return Reply::empty(416);
            };
            let end = end
                .parse::<usize>()
                .unwrap_or(usize::MAX)
                .min(object.data.len().saturating_sub(1));
            if start > end || start >= object.data.len() {
                return Reply::empty(416);
            }
            reply.status = 206;
            reply.body = object.data[start..=end].to_vec();
            reply = reply.header(
                "Content-Range",
                format!("bytes {start}-{end}/{}", object.data.len()),
            );
        } else {
            reply.body = object.data.clone();
        }
        reply
    }

    fn put(&mut self, req: &Incoming) -> Reply {
        if req.query.contains_key("metadata") {
            let Some(object) = self.objects.get_mut(&req.key) else {
                return Reply::error(404, "NoSuchKey");
            };
            match req.header("x-obs-metadata-directive") {
                "REPLACE_NEW" => object.meta.retain(|k, _| !k.starts_with("x-obs-meta-")),
                "REPLACE" => object.meta.clear(),
                _ => return Reply::error(400, "InvalidArgument"),
            }
            object.meta.extend(req.meta());
            return Reply::empty(200);
        }
        if let (Some(id), Some(source)) = (
            req.query.get("uploadId"),
            req.headers.get("x-obs-copy-source"),
        ) {
            let key = decode(strip_bucket(source));
            let Some(object) = self.objects.get(&key) else {
                return Reply::error(404, "NoSuchKey");
            };
            if req.header("x-obs-copy-source-if-match") != object.etag() {
                return Reply::empty(412);
            }
            let Some(range) = req.header("x-obs-copy-source-range").strip_prefix("bytes=") else {
                return Reply::empty(400);
            };
            let Some((start, end)) = range
                .split_once('-')
                .and_then(|(a, b)| Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?)))
            else {
                return Reply::empty(400);
            };
            let Some(data) = object.data.get(start..=end) else {
                return Reply::empty(416);
            };
            let data = data.to_vec();
            let Some(upload) = self.uploads.get_mut(id) else {
                return Reply::error(404, "NoSuchUpload");
            };
            let number = req
                .query
                .get("partNumber")
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let etag = md5_hex(&data);
            upload.parts.insert(number, data);
            return Reply::xml(
                200,
                format!("<CopyPartResult><ETag>{etag}</ETag></CopyPartResult>"),
            );
        }
        if let Some(id) = req.query.get("uploadId") {
            let Some(upload) = self.uploads.get_mut(id).filter(|u| u.key == req.key) else {
                return Reply::error(404, "NoSuchUpload");
            };
            let Some(number) = req
                .query
                .get("partNumber")
                .and_then(|n| n.parse::<u32>().ok())
                .filter(|n| *n > 0)
            else {
                return Reply::error(400, "InvalidArgument");
            };
            upload.parts.insert(number, req.body.clone());
            return Reply::empty(200).header("ETag", format!("\"{}\"", md5_hex(&req.body)));
        }
        if let Some(source) = req.headers.get("x-obs-copy-source") {
            let key = decode(strip_bucket(source));
            let Some(mut object) = self.objects.get(&key).cloned() else {
                return Reply::error(404, "NoSuchKey");
            };
            if let Some(tag) = req.headers.get("x-obs-copy-source-if-match")
                && tag != &object.etag()
            {
                return Reply::empty(412);
            }
            if req
                .header("x-obs-metadata-directive")
                .eq_ignore_ascii_case("REPLACE")
            {
                object.meta = req.meta();
            }
            let etag = object.etag();
            self.objects.insert(req.key.clone(), object);
            return Reply::xml(
                200,
                format!("<CopyObjectResult><ETag>{etag}</ETag></CopyObjectResult>"),
            );
        }
        let object = Object::new(req.body.clone(), req.meta());
        let etag = object.etag();
        self.objects.insert(req.key.clone(), object);
        Reply::empty(200).header("ETag", etag)
    }

    fn post(&mut self, req: &Incoming) -> Reply {
        if req.query.contains_key("uploads") {
            self.sequence += 1;
            let id = format!("upload-{:04}", self.sequence);
            self.uploads.insert(
                id.clone(),
                Upload {
                    key: req.key.clone(),
                    parts: BTreeMap::new(),
                    meta: req.meta(),
                },
            );
            return Reply::xml(
                200,
                format!(
                    "<InitiateMultipartUploadResult><Bucket>{BUCKET}</Bucket><Key>{}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>",
                    escape(&req.key)
                ),
            );
        }
        let Some(id) = req.query.get("uploadId") else {
            return Reply::error(400, "BadRequest");
        };
        let Some(upload) = self.uploads.get(id).filter(|u| u.key == req.key) else {
            return Reply::error(404, "NoSuchUpload");
        };
        let Ok(parts) = completion_parts(&req.body) else {
            return Reply::error(400, "MalformedXML");
        };
        if parts.is_empty() {
            return Reply::error(400, "MalformedXML");
        }
        let mut data = Vec::new();
        for (i, (number, etag)) in parts.iter().enumerate() {
            if *number != i as u32 + 1 {
                return Reply::error(400, "InvalidPartOrder");
            }
            let Some(part) = upload.parts.get(number) else {
                return Reply::error(400, "InvalidPart");
            };
            if etag.trim_matches('"') != md5_hex(part) {
                return Reply::error(400, "InvalidPart");
            }
            data.extend_from_slice(part);
        }
        let upload = self.uploads.remove(id).unwrap();
        let etag = format!("\"{}-{}\"", md5_hex(&data), parts.len());
        self.objects
            .insert(req.key.clone(), Object::new(data, upload.meta));
        Reply::xml(
            200,
            format!(
                "<CompleteMultipartUploadResult><Key>{}</Key><ETag>{etag}</ETag></CompleteMultipartUploadResult>",
                escape(&req.key)
            ),
        )
    }

    fn list(&self, req: &Incoming) -> Reply {
        let param = |name: &str| req.query.get(name).map(String::as_str).unwrap_or("");
        let prefix = param("prefix");
        let delimiter = param("delimiter");
        let marker = param("marker");
        let max = param("max-keys").parse::<usize>().unwrap_or(1000);
        let mut entries = BTreeMap::new();
        for (key, object) in &self.objects {
            let Some(rest) = key.strip_prefix(prefix) else {
                continue;
            };
            if !delimiter.is_empty()
                && let Some((first, _)) = rest.split_once(delimiter)
            {
                let common = format!("{prefix}{first}{delimiter}");
                if common.as_str() > marker {
                    entries.insert(common, None);
                }
            } else if key.as_str() > marker {
                entries.insert(key.clone(), Some(object));
            }
        }
        let truncated = entries.len() > max;
        let mut xml = format!(
            "<ListBucketResult><Name>{BUCKET}</Name><Prefix>{}</Prefix><Marker>{}</Marker><MaxKeys>{max}</MaxKeys><IsTruncated>{truncated}</IsTruncated>",
            escape(prefix),
            escape(marker)
        );
        let mut next_marker = String::new();
        for (key, object) in entries.into_iter().take(max) {
            if let Some(object) = object {
                xml.push_str(&format!("<Contents><Key>{}</Key><LastModified>{}</LastModified><Size>{}</Size><ETag>{}</ETag><StorageClass>STANDARD</StorageClass></Contents>", escape(&key), object.modified, object.data.len(), object.etag()));
            } else {
                xml.push_str(&format!(
                    "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                    escape(&key)
                ));
            }
            next_marker = key;
        }
        if truncated {
            xml.push_str(&format!(
                "<NextMarker>{}</NextMarker>",
                escape(&next_marker)
            ));
        }
        xml.push_str("</ListBucketResult>");
        Reply::xml(200, xml)
    }
}

fn completion_parts(body: &[u8]) -> Result<Vec<(u32, String)>, quick_xml::Error> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(body);
    let mut parts = Vec::new();
    let (mut number, mut etag) = (None, None);
    loop {
        match reader.read_event()? {
            Event::Start(e) if e.name().as_ref() == "PartNumber" => {
                number = reader.read_text(e.name())?.parse().ok();
            }
            Event::Start(e) if e.name().as_ref() == "ETag" => {
                let text = reader.read_text(e.name())?;
                etag = Some(
                    quick_xml::escape::unescape(&text)
                        .map_err(quick_xml::Error::from)?
                        .into_owned(),
                );
            }
            Event::End(e) if e.name().as_ref() == "Part" => {
                parts.push((number.take().unwrap_or(0), etag.take().unwrap_or_default()));
            }
            Event::Eof => return Ok(parts),
            _ => {}
        }
    }
}

pub struct MockObs {
    _server: MockServer,
    pub endpoint: String,
    pub staging: PathBuf,
}

impl MockObs {
    pub fn new(faults: &str) -> Self {
        Self::with_config(Config {
            faults: serde_json::from_str(faults).expect("valid mock fault configuration"),
            ..Default::default()
        })
    }

    pub fn with_config(config: Config) -> Self {
        let server = MockServer::start(config).expect("mock OBS listener");
        Self {
            endpoint: server.endpoint.clone(),
            _server: server,
            staging: crate::staging_dir_for(&std::env::temp_dir(), crate::current_uid()).unwrap(),
        }
    }

    pub fn client(&self) -> ObsClient {
        ObsClient::new(
            "TESTAK".into(),
            "TESTSK".into(),
            "test-bucket".into(),
            self.endpoint.clone(),
        )
    }

    pub fn stats(&self) -> Stats {
        let text = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("{}/__stats", self.endpoint))
            .send()
            .unwrap()
            .text()
            .unwrap();
        serde_json::from_str(&text).unwrap()
    }
}

impl Drop for MockObs {
    fn drop(&mut self) {
        // Never walk through a mount if teardown failed: it could delete OBS data.
        let root = mount_path(&self.staging);
        let safe = mount_paths().is_ok_and(|paths| {
            !paths
                .iter()
                .any(|path| path == &root || path.starts_with(&format!("{root}/")))
        });
        if safe {
            let _ = std::fs::remove_dir_all(&self.staging);
        } else {
            eprintln!(
                "retaining test directory with a possible mount: {}",
                self.staging.display()
            );
        }
    }
}

/// The real binary is only needed by explicitly requested CLI/mount tests.
pub fn mount_binary() -> PathBuf {
    let binary = std::env::var_os("OBS_MOUNT_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/release/obs-mount")
        });
    assert!(
        binary.is_file(),
        "build the binary with cargo build --release, or set OBS_MOUNT_BIN"
    );
    binary
}

fn mount_paths() -> io::Result<Vec<String>> {
    Ok(std::fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4).map(str::to_owned))
        .collect())
}

fn mount_path(path: &std::path::Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\134")
        .replace(' ', "\\040")
        .replace('\t', "\\011")
        .replace('\n', "\\012")
}

pub fn is_mounted(path: &std::path::Path) -> bool {
    let target = mount_path(path);
    mount_paths().expect("read mount table").contains(&target)
}

/// Owns one test child and its mount. Drop unmounts only this child's directory.
pub struct MountProcess {
    pub mountpoint: PathBuf,
    log: PathBuf,
    child: std::process::Child,
}

impl MountProcess {
    pub fn spawn(mock: &MockObs, name: &str, identity: Option<(u32, u32)>) -> Self {
        use std::fs::{self, File};
        use std::os::unix::fs::{PermissionsExt, chown};
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        #[derive(Serialize)]
        struct MountConfig<'a> {
            mountpoint: &'a std::path::Path,
            bucket: &'a str,
            endpoint: &'a str,
            ak: &'a str,
            sk: &'a str,
        }
        let mountpoint = mock.staging.join(name);
        let temp = mock.staging.join(format!("{name}-tmp"));
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&temp).unwrap();
        let config = mock.staging.join(format!("{name}.yaml"));
        let yaml = serde_yaml::to_string(&MountConfig {
            mountpoint: &mountpoint,
            bucket: BUCKET,
            endpoint: &mock.endpoint,
            ak: AK,
            sk: SK,
        })
        .unwrap();
        fs::write(&config, yaml).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o700)).unwrap();
        let mut binary = mount_binary();
        if let Some((uid, gid)) = identity {
            // Do not depend on the checkout being traversable by another user.
            let copy = mock.staging.join(format!("{name}-bin"));
            fs::copy(&binary, &copy).unwrap();
            fs::set_permissions(&copy, fs::Permissions::from_mode(0o755)).unwrap();
            binary = copy;
            for path in [&mountpoint, &temp, &config] {
                chown(path, Some(uid), Some(gid)).unwrap();
            }
        }
        let log = mock.staging.join(format!("{name}.log"));
        let output = File::create(&log).unwrap();
        let mut command = Command::new(binary);
        command
            .arg("-c")
            .arg(&config)
            .env("TMPDIR", temp)
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .process_group(0);
        for key in [
            "OBS_BUCKET",
            "OBS_ENDPOINT",
            "OBS_AK",
            "OBS_SK",
            "OBS_MULTIPART_THRESHOLD",
            "OBS_MULTIPART_PART_SIZE",
            "OBS_UPLOAD_CONCURRENCY",
            "OBS_MIN_FREE_SPACE",
            "OBS_METADATA_CACHE_ENTRIES",
            "OBS_REQUEST_TIMEOUT_SECS",
            "OBS_TRANSFER_TIMEOUT_SECS",
        ] {
            command.env_remove(key);
        }
        if let Some((uid, gid)) = identity {
            command.uid(uid).gid(gid);
        }
        let child = command.spawn().expect("start obs-mount");
        Self {
            mountpoint,
            log,
            child,
        }
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    pub fn wait_mounted(&mut self) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if is_mounted(&self.mountpoint) {
                return true;
            }
            if self.child.try_wait().unwrap().is_some() {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }

    pub fn wait_exit(&mut self) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "mount process did not exit: {}",
                self.log()
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn terminate(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "mount already exited: {}",
            self.log()
        );
        // Signal only the child owned by this guard, never a name or PID search.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) },
            0
        );
        let status = self.wait_exit();
        assert!(
            status.success(),
            "mount did not shut down cleanly ({status}): {}",
            self.log()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while is_mounted(&self.mountpoint) && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            !is_mounted(&self.mountpoint),
            "SIGTERM left a stale mount {}: {}",
            self.mountpoint.display(),
            self.log()
        );
    }
}

impl Drop for MountProcess {
    fn drop(&mut self) {
        use std::process::{Command, Stdio};
        let _ = self.child.kill();
        let _ = self.child.wait();
        if is_mounted(&self.mountpoint) {
            for (helper, flag) in [("fusermount3", "-uz"), ("umount", "-l")] {
                let _ = Command::new(helper)
                    .args([flag, "--"])
                    .arg(&self.mountpoint)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                if !is_mounted(&self.mountpoint) {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, MockServer, Stats};
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use hmac::{Hmac, KeyInit, Mac};
    use md5::{Digest, Md5};
    use reqwest::blocking::{Client, RequestBuilder};
    use sha1::Sha1;
    use std::time::Duration;

    const DATE: &str = "Tue, 03 Nov 2026 06:26:00 GMT";

    fn client() -> Client {
        Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn stats(client: &Client, server: &MockServer) -> Stats {
        serde_json::from_str(
            &client
                .get(format!("{}/__stats", server.endpoint))
                .send()
                .unwrap()
                .text()
                .unwrap(),
        )
        .unwrap()
    }

    fn signed(
        client: &Client,
        server: &MockServer,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> RequestBuilder {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let mut subs: Vec<_> = query
            .split('&')
            .filter(|q| {
                matches!(
                    q.split('=').next(),
                    Some("uploads" | "uploadId" | "partNumber" | "quota" | "storageinfo")
                )
            })
            .collect();
        subs.sort_unstable();
        let resource = if subs.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{}", subs.join("&"))
        };
        let md5 = B64.encode(Md5::digest(body));
        let mut mac = Hmac::<Sha1>::new_from_slice(b"TESTSK").unwrap();
        mac.update(format!("{method}\n{md5}\n\n{DATE}\n{resource}").as_bytes());
        client
            .request(
                method.parse().unwrap(),
                format!("{}{target}", server.endpoint),
            )
            .header("Date", DATE)
            .header("Content-MD5", md5)
            .header(
                "Authorization",
                format!("OBS TESTAK:{}", B64.encode(mac.finalize().into_bytes())),
            )
            .body(body.to_vec())
    }

    #[test]
    fn fixed_signatures_pin_encoded_paths_and_the_empty_date_slot() {
        let server = MockServer::start(Config::default()).unwrap();
        let client = client();
        // Fixed vectors generated outside Rust with OpenSSL HMAC-SHA1, key TESTSK.
        // These do not call the fixture or production signing helpers.
        let response = client
            .get(format!("{}/test-bucket/", server.endpoint))
            .header("Date", DATE)
            .header("Authorization", "OBS TESTAK:yFMj5/BQSt4xI8IuO43gdG81mvw=")
            .send()
            .unwrap();
        assert_eq!(response.status(), 200);
        let target = "/test-bucket/a%20b%2B%E4%B8%AD.txt";
        let put = || {
            client
                .put(format!("{}{target}", server.endpoint))
                .header("Date", DATE)
                .header("Authorization", "OBS TESTAK:0iR/zCNngqvODUnH9OQ4Z/6bajI=")
                .body("payload")
        };
        assert_eq!(put().send().unwrap().status(), 200);
        let data = signed(&client, &server, "GET", target, b"")
            .send()
            .unwrap()
            .bytes()
            .unwrap();
        assert_eq!(&data[..], b"payload");
        // Changing only the signed header must invalidate the fixed signature.
        assert_eq!(
            put().header("Date", "wrong date").send().unwrap().status(),
            403
        );
        let dated = || {
            client
                .put(format!("{}/test-bucket/dated", server.endpoint))
                .header("Date", "ignored when x-obs-date is present")
                .header("x-obs-date", DATE)
                .header("Authorization", "OBS TESTAK:H2D8bDFsS0qGD526mMWuX5eOKvU=")
                .body("data")
        };
        assert_eq!(dated().send().unwrap().status(), 200);
        assert_eq!(
            dated()
                .header("x-obs-date", "wrong date")
                .send()
                .unwrap()
                .status(),
            403
        );
        assert_eq!(stats(&client, &server).signature_failures, 2);
    }

    #[test]
    fn rejects_missing_auth_and_a_body_that_does_not_match_content_md5() {
        let server = MockServer::start(Config::default()).unwrap();
        let client = client();
        assert_eq!(
            client
                .put(format!("{}/test-bucket/key", server.endpoint))
                .body("data")
                .send()
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            signed(&client, &server, "PUT", "/test-bucket/key", b"original")
                .body("corrupt")
                .send()
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            signed(&client, &server, "PUT", "/test-bucket/key", b"original")
                .body("")
                .send()
                .unwrap()
                .status(),
            403
        );
        let stats = stats(&client, &server);
        assert_eq!(stats.signature_failures, 3);
        assert_eq!(stats.objects, 0);
    }

    #[test]
    fn chunked_upload_head_range_and_conditional_get_round_trip() {
        let server = MockServer::start(Config::default()).unwrap();
        let client = client();
        let target = "/test-bucket/stream";
        let body = b"0123456789";
        assert_eq!(
            signed(&client, &server, "PUT", target, body)
                .body(reqwest::blocking::Body::new(std::io::Cursor::new(
                    body.to_vec()
                )))
                .send()
                .unwrap()
                .status(),
            200
        );
        let head = signed(&client, &server, "HEAD", target, b"")
            .send()
            .unwrap();
        assert_eq!(head.headers()["content-length"], "10");
        let etag = head.headers()["etag"].clone();
        assert!(head.bytes().unwrap().is_empty());
        let range = signed(&client, &server, "GET", target, b"")
            .header("Range", "bytes=3-6")
            .header("If-Match", etag)
            .send()
            .unwrap();
        assert_eq!(range.status(), 206);
        assert_eq!(range.headers()["content-range"], "bytes 3-6/10");
        assert_eq!(range.text().unwrap(), "3456");
        assert_eq!(
            signed(&client, &server, "GET", target, b"")
                .header("If-Match", "\"wrong\"")
                .send()
                .unwrap()
                .status(),
            412
        );
        assert_eq!(
            signed(&client, &server, "GET", target, b"")
                .header("Range", "bytes=10-20")
                .send()
                .unwrap()
                .status(),
            416
        );
    }

    #[test]
    fn pagination_keeps_every_key_and_prefix_and_preserves_literal_plus() {
        let server = MockServer::start(Config::default()).unwrap();
        let client = client();
        for key in [
            "a+first",
            "a+folder/one",
            "a+folder/two",
            "a+last&<>",
            "other",
        ] {
            let key = urlencoding::encode(key);
            assert_eq!(
                signed(
                    &client,
                    &server,
                    "PUT",
                    &format!("/test-bucket/{key}"),
                    b"x"
                )
                .send()
                .unwrap()
                .status(),
                200
            );
        }
        let first = signed(
            &client,
            &server,
            "GET",
            "/test-bucket/?prefix=a+&delimiter=/&max-keys=2",
            b"",
        )
        .send()
        .unwrap()
        .text()
        .unwrap();
        assert!(first.contains("<Key>a+first</Key>"));
        assert!(first.contains("<CommonPrefixes><Prefix>a+folder/</Prefix>"));
        assert!(first.contains("<IsTruncated>true</IsTruncated>"));
        assert!(first.contains("<NextMarker>a+folder/</NextMarker>"));
        let second = signed(
            &client,
            &server,
            "GET",
            "/test-bucket/?prefix=a+&delimiter=/&max-keys=2&marker=a%2Bfolder%2F",
            b"",
        )
        .send()
        .unwrap()
        .text()
        .unwrap();
        assert!(second.contains("<Key>a+last&amp;&lt;&gt;</Key>"));
        assert!(second.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!second.contains("<CommonPrefixes>"));
    }

    #[test]
    fn bucket_configuration_and_fault_counts_are_isolated() {
        let server = MockServer::start(Config {
            quota: 1024,
            file_bucket: true,
            faults: serde_json::from_str(
                r#"[{"method":"GET","key":"","query":"quota","status":403,"count":2}]"#,
            )
            .unwrap(),
        })
        .unwrap();
        let other = MockServer::start(Config::default()).unwrap();
        let client = client();
        let head = signed(&client, &server, "HEAD", "/test-bucket/", b"")
            .send()
            .unwrap();
        assert_eq!(head.headers()["x-obs-bucket-type"], "POSIX");
        for _ in 0..2 {
            assert_eq!(
                signed(&client, &server, "GET", "/test-bucket/?quota", b"")
                    .send()
                    .unwrap()
                    .status(),
                403
            );
        }
        let quota = signed(&client, &server, "GET", "/test-bucket/?quota", b"")
            .send()
            .unwrap()
            .text()
            .unwrap();
        assert!(quota.contains("<StorageQuota>1024</StorageQuota>"));
        assert_eq!(
            signed(&client, &server, "PUT", "/test-bucket/only-here", b"data")
                .send()
                .unwrap()
                .status(),
            200
        );
        let usage = signed(&client, &server, "GET", "/test-bucket/?storageinfo", b"")
            .send()
            .unwrap()
            .text()
            .unwrap();
        assert!(usage.contains("<Size>4</Size><ObjectNumber>1</ObjectNumber>"));
        assert_eq!(stats(&client, &server).signature_failures, 0);
        assert_eq!(stats(&client, &other).objects, 0);
        assert!(
            !signed(&client, &other, "HEAD", "/test-bucket/", b"")
                .send()
                .unwrap()
                .headers()
                .contains_key("x-obs-bucket-type")
        );
    }

    #[test]
    fn invalid_multipart_completion_keeps_parts_until_abort() {
        let server = MockServer::start(Config::default()).unwrap();
        let client = client();
        let init = signed(&client, &server, "POST", "/test-bucket/backup?uploads", b"")
            .send()
            .unwrap()
            .text()
            .unwrap();
        let id = init
            .split("<UploadId>")
            .nth(1)
            .unwrap()
            .split("</UploadId>")
            .next()
            .unwrap();
        assert_eq!(
            signed(
                &client,
                &server,
                "PUT",
                &format!("/test-bucket/backup?partNumber=1&uploadId={id}"),
                b"part"
            )
            .send()
            .unwrap()
            .status(),
            200
        );
        let complete = format!("/test-bucket/backup?uploadId={id}");
        let invalid = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>wrong</ETag></Part></CompleteMultipartUpload>";
        assert_eq!(
            signed(&client, &server, "POST", &complete, invalid)
                .send()
                .unwrap()
                .status(),
            400
        );
        assert_eq!(stats(&client, &server).uploads, 1);
        assert_eq!(stats(&client, &server).objects, 0);
        assert_eq!(
            signed(&client, &server, "DELETE", &complete, b"")
                .send()
                .unwrap()
                .status(),
            204
        );
        assert_eq!(stats(&client, &server).uploads, 0);
    }
}
