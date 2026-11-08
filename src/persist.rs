use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Replace one private recovery record and durably publish its directory entry.
pub fn write_yaml(path: &Path, value: &impl serde::Serialize) -> std::io::Result<()> {
    let bytes = serde_yaml::to_string(value).map_err(std::io::Error::other)?;
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    let temp = Path::new(&name);
    let result = (|| {
        let mut file = File::create(temp)?;
        file.write_all(bytes.as_bytes())?;
        file.sync_all()?;
        fs::rename(temp, path)?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
