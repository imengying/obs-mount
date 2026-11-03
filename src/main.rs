mod fs;
mod obs;

use clap::Parser;
use fs::ObsFs;
use fuser::MountOption;
use obs::{BucketKind, ObsClient};
use serde::Deserialize;
use std::path::PathBuf;

/// Configuration file contents (YAML only). Every field is optional:
/// anything missing here can still come from a command-line flag or an
/// environment variable, which take precedence over the file.
/// Precedence: CLI flag > environment variable > config file.
/// Unknown fields are rejected at startup (`deny_unknown_fields`)
/// instead of being silently ignored.
/// The file itself is the recommended home for AK/SK and the mountpoint:
/// keep it at 0600, e.g. /etc/obs/obs-mount.yaml.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    mountpoint: Option<PathBuf>,
    bucket: Option<String>,
    endpoint: Option<String>,
    ak: Option<String>,
    sk: Option<String>,
    multipart_threshold: Option<u64>,
    /// Multipart chunk size in bytes. Optional; obsfs mounts with 10 MB,
    /// the default here is 10 MB. Raised automatically for files big enough
    /// to exceed the 10000-part limit.
    multipart_part_size: Option<usize>,
}

impl FileConfig {
    fn load(path: &PathBuf) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config file {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path)
                && meta.permissions().mode() & 0o077 != 0
            {
                tracing::warn!(
                    path = %path.display(),
                    "config file holds credentials but is readable by group/other; run: chmod 0600 {}",
                    path.display()
                );
            }
        }
        serde_yaml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("cannot parse config file {}: {e}", path.display()))
    }
}

/// Mount a Huawei Cloud OBS bucket as a local directory (FUSE).
///
/// Native OBS REST signing only (HMAC-SHA1, `Authorization: OBS AK:...`,
/// `x-obs-*` headers) — no S3/SigV4 code path.
///
/// Credentials come from a config file (YAML, see --config),
/// the environment, or a flag — never put them on the command line in
/// a way that shows up in `ps` output for a shared machine; prefer the
/// file. Example /etc/obs/obs-mount.yaml:
///
/// ```yaml
/// mountpoint: /mnt/obs
/// bucket: my-bucket
/// endpoint: https://my-bucket.obs.cn-north-4.myhuaweicloud.com
/// ak: YOUR_ACCESS_KEY_HERE
/// sk: YOUR_SECRET_KEY_HERE
/// ```
///
/// The endpoint may be either the *bucket* virtual host
/// (`https://<bucket>.obs.<region>.myhuaweicloud.com`) or the bare service
/// endpoint (`https://obs.<region>.myhuaweicloud.com`, bucket taken from
/// the separate `bucket` setting); the addressing style is derived from the
/// host, and IP endpoints such as `http://10.0.0.1:9000` fall back to
/// path-style automatically. Replace `<region>` with the region your bucket
/// lives in; do not mount across regions.
///
/// A POSIX/file-type OBS bucket is refused at startup: this program
/// implements object-bucket semantics and a file bucket is already POSIX.
///
/// Backup use case: copy a file into the mountpoint and close it — the
/// upload happens on close. Verify with `ls` / `sha256sum` (a Range GET)
/// or in the OBS console. Do not run databases or VM images on the mount:
///
/// OBS objects are immutable, rename is Copy+Delete (not atomic), and
/// every fsync/close re-uploads the whole file.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Config file (YAML) to read at startup. Defaults to
    /// $OBS_MOUNT_CONFIG, else /etc/obs/obs-mount.yaml if it exists.
    /// Flags and env vars override values from the file.
    #[arg(long, env = "OBS_MOUNT_CONFIG")]
    config: Option<PathBuf>,

    /// Local directory to mount on (must exist and be empty).
    /// Falls back to `mountpoint` in the config file.
    mountpoint: Option<PathBuf>,

    /// OBS bucket name. Defaults to $OBS_BUCKET, else config file.
    #[arg(long, env = "OBS_BUCKET")]
    bucket: Option<String>,

    /// Bucket virtual-host endpoint, e.g.
    /// https://my-bucket.obs.cn-north-4.myhuaweicloud.com
    /// Defaults to $OBS_ENDPOINT, else config file.
    #[arg(long, env = "OBS_ENDPOINT")]
    endpoint: Option<String>,

    /// Access key. Defaults to $OBS_AK, else config file.
    #[arg(long, env = "OBS_AK", hide_env_values = true)]
    ak: Option<String>,

    /// Secret key. Defaults to $OBS_SK, else config file.
    #[arg(long, env = "OBS_SK", hide_env_values = true)]
    sk: Option<String>,

    /// Files at or above this size use multipart upload (bytes).
    /// Optional: defaults to $OBS_MULTIPART_THRESHOLD, else config file,
    /// else 26214400 (25 MB) when not configured anywhere.
    #[arg(long, env = "OBS_MULTIPART_THRESHOLD")]
    multipart_threshold: Option<u64>,

    /// Multipart chunk size in bytes (default 10485760, i.e. 10 MB, matching
    /// Huawei's obsfs). OBS requires at least 5 MiB.
    #[arg(long, env = "OBS_MULTIPART_PART_SIZE")]
    multipart_part_size: Option<usize>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    // Resolve the config file: explicit --config wins, otherwise the
    // first default location that exists; no file at all is fine as long
    // as every required value comes from a flag or the environment.
    let config_path = args.config.clone().or_else(|| {
        let p = PathBuf::from("/etc/obs/obs-mount.yaml");
        p.is_file().then_some(p)
    });
    let cfg = match &config_path {
        Some(p) => FileConfig::load(p)?,
        None => FileConfig::default(),
    };
    let missing = |name: &str| {
        anyhow::anyhow!(
            "{name} is not set: pass the flag, set the env var, or put it in the config file"
        )
    };
    let mountpoint = args
        .mountpoint
        .or(cfg.mountpoint)
        .ok_or_else(|| missing("mountpoint"))?;
    if !mountpoint.is_dir() {
        anyhow::bail!("mountpoint {} is not a directory", mountpoint.display());
    }
    let bucket = args
        .bucket
        .or(cfg.bucket)
        .ok_or_else(|| missing("bucket"))?;
    let endpoint = args
        .endpoint
        .or(cfg.endpoint)
        .ok_or_else(|| missing("endpoint"))?;
    let ak = args.ak.or(cfg.ak).ok_or_else(|| missing("ak"))?;
    let sk = args.sk.or(cfg.sk).ok_or_else(|| missing("sk"))?;
    let multipart_threshold = args
        .multipart_threshold
        .or(cfg.multipart_threshold)
        .unwrap_or(obs::DEFAULT_MULTIPART_THRESHOLD);
    if multipart_threshold == 0 {
        anyhow::bail!(
            "multipart_threshold must not be 0 (a 0-byte threshold would send even empty files as multipart)"
        );
    }
    // Staging is not configurable: always under the system temp dir
    // (std::env::temp_dir(), i.e. $TMPDIR or /tmp on Linux), so a
    // half-written file never needs a hand-picked directory.
    let staging_dir = std::env::temp_dir().join("obs-mount-staging");
    std::fs::create_dir_all(&staging_dir)?;
    let client = ObsClient::new(ak, sk, bucket.clone(), endpoint.clone());
    tracing::info!(
        endpoint = %endpoint,
        addressing = if client.uses_path_style() { "path-style (/bucket/key)" } else { "virtual-host (bucket.host/key)" },
        "OBS client configured"
    );
    // Startup self-check 1: refuse a POSIX/file bucket.
    //
    // OBS exposes both flat object buckets and POSIX file buckets behind the
    // same endpoint. This program implements object-bucket semantics
    // (placeholder objects for directories, copy+delete rename, whole-file
    // uploads), so running it against a file bucket would silently misbehave.
    // Huawei's obsfs makes the same distinction via `HEAD /` and
    // x-obs-bucket-type / x-obs-fs-file-interface.
    match client.bucket_kind() {
        Ok(BucketKind::File) => {
            anyhow::bail!(
                "bucket {bucket} is an OBS POSIX/file bucket (HEAD / reports x-obs-bucket-type: POSIX). \
                 This program only supports object buckets; a file bucket is already POSIX and \
                 does not need a FUSE translation layer."
            );
        }
        Ok(BucketKind::Object) => tracing::debug!(bucket = %bucket, "bucket is an object bucket"),
        Ok(BucketKind::Unknown) => tracing::debug!(
            bucket = %bucket,
            "bucket type not reported; assuming an object bucket"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "HEAD / for bucket-type detection failed; continuing, the listing check below decides"
        ),
    }
    // Startup self-check 2: the bucket must be listable before we mount,
    // otherwise a bad AK/SK or region shows up as an empty-looking mount.
    match client.list_dir("") {
        Ok(_) => {
            tracing::info!(bucket = %bucket, mountpoint = %mountpoint.display(), "OBS bucket reachable, mounting")
        }
        Err(e) => {
            tracing::error!(error = %e, "OBS bucket check failed; refusing to mount (check AK/SK, bucket, region/endpoint, and clock/NTP)");
            anyhow::bail!("OBS bucket check failed: {e}");
        }
    }
    let part_size = args
        .multipart_part_size
        .or(cfg.multipart_part_size)
        .unwrap_or(obs::DEFAULT_PART_SIZE);
    if part_size < 5 * 1024 * 1024 {
        anyhow::bail!(
            "multipart_part_size must be at least 5 MiB (OBS minimum part size), got {part_size}"
        );
    }
    let upload = obs::UploadTuning {
        threshold: multipart_threshold,
        part_size,
    };
    tracing::info!(
        threshold = upload.threshold,
        part_size = upload.part_size,
        "upload tuning"
    );
    let fs = ObsFs::new(client, staging_dir, upload);
    // fuser 0.18: allow-root moved from MountOption to the session ACL.
    // allow_root is always on (the mount is normally run as root anyway):
    // root plus the mounting user can see the mount. There is no
    // allow_other option — other users do not get access.
    //
    // AutoUnmount is only possible through the setuid `fusermount` helper:
    // fuser refuses to take the direct /dev/fuse path when that option is
    // present, and if the helper is missing the mount dies with a bare
    // `ENOENT` that says nothing about a missing package. So probe for the
    // helper first and fall back to a plain mount (unmounted by the kernel
    // when the process dies, only not lazily detached) instead of failing.
    let mut mount_options = vec![
        MountOption::FSName("obs-mount".to_string()),
        MountOption::DefaultPermissions,
    ];
    match fusermount_bin() {
        Some(bin) => {
            tracing::debug!(helper = %bin, "using fusermount helper (auto_unmount enabled)");
            mount_options.push(MountOption::AutoUnmount);
        }
        None => tracing::warn!(
            "fusermount/fusermount3 not found: mounting without auto_unmount. \
             Install the fuse3 package (Debian/Ubuntu: apt-get install fuse3) to get \
             automatic lazy unmount on exit."
        ),
    }
    let acl = fuser::SessionACL::RootAndOwner;
    // Config is #[non_exhaustive], so build it from Default and mutate.
    let mut config = fuser::Config::default();
    config.mount_options = mount_options;
    config.acl = acl;
    fuser::mount(fs, &mountpoint, &config).map_err(|e| {
        anyhow::anyhow!(
            "cannot mount {}: {e}\n\
             If this says 'No such file or directory' while /dev/fuse exists, the \
             fusermount helper is missing: apt-get install fuse3.",
            mountpoint.display()
        )
    })?;
    Ok(())
}

/// Locate the setuid FUSE mount helper, mirroring fuser's own lookup order
/// (`$FUSERMOUNT_PATH`, then fusermount3, then fusermount).
fn fusermount_bin() -> Option<String> {
    if let Some(p) = std::env::var_os("FUSERMOUNT_PATH") {
        let p = p.to_string_lossy().into_owned();
        if is_executable(&p) {
            return Some(p);
        }
    }
    ["fusermount3", "fusermount"]
        .into_iter()
        .find(|name| search_path(name).is_some())
        .map(|name| search_path(name).unwrap_or_else(|| name.to_string()))
}

fn search_path(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| is_executable(&p.to_string_lossy()))
        .map(|p| p.to_string_lossy().into_owned())
}

fn is_executable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_config_field_is_rejected_not_ignored() {
        // Any unknown field fails, no special-casing.
        let bad = "mountpoint: /mnt/obs\nbucket: b\nfoo: bar\n";
        assert!(serde_yaml::from_str::<FileConfig>(bad).is_err());
        let ok = "mountpoint: /mnt/obs\nbucket: b\nmultipart_threshold: 26214400\n";
        let cfg = serde_yaml::from_str::<FileConfig>(ok).unwrap();
        assert_eq!(cfg.multipart_threshold, Some(26_214_400));
    }
}
