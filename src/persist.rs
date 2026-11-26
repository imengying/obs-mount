use std::fs::{self, File};
use std::io::Write;
use std::mem::DropGuard;
use std::path::Path;

/// Replace one private recovery record and durably publish its directory entry.
pub fn write_yaml(path: &Path, value: &impl serde::Serialize) -> std::io::Result<()> {
    let bytes = yaml_serde::to_string(value).map_err(std::io::Error::other)?;
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    let temp = Path::new(&name);
    let cleanup = DropGuard::new(temp, |temp| {
        let _ = fs::remove_file(temp);
    });
    let mut file = File::create(temp)?;
    file.write_all(bytes.as_bytes())?;
    file.sync_all()?;
    fs::rename(temp, path)?;
    DropGuard::dismiss(cleanup);
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_publish_keeps_destination_and_removes_temporary_record() {
        let dir = crate::staging_dir_for(&std::env::temp_dir(), crate::current_uid()).unwrap();
        let dir = DropGuard::new(dir, |dir| {
            let _ = fs::remove_dir_all(dir);
        });
        let path = dir.join("record.yaml");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), b"existing data").unwrap();

        // The temporary record can be written, but cannot replace a directory.
        assert!(write_yaml(&path, &"new record").is_err());
        assert_eq!(fs::read(path.join("keep")).unwrap(), b"existing data");
        assert!(!dir.join("record.yaml.tmp").exists());

        fs::remove_dir_all(&path).unwrap();
        write_yaml(&path, &"new record").unwrap();
        let record: String = yaml_serde::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(record, "new record");
        assert!(!dir.join("record.yaml.tmp").exists());
    }
}
