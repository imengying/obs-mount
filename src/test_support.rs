//! A real HTTP fixture, usable without /dev/fuse. Each test starts its own
//! server so fault injection stays isolated, and gets its own freshly created
//! staging directory to write into.
use crate::obs::ObsClient;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

pub struct MockObs {
    child: Child,
    pub endpoint: String,
    pub staging: PathBuf,
}

impl MockObs {
    pub fn new(faults: &str) -> Self {
        let mut child = Command::new("python3")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/mock_obs.py"))
            .arg("0")
            .env("OBS_MOCK_FAULTS", faults)
            .stdout(Stdio::piped())
            .spawn()
            .expect("python3 is required for the mock OBS tests");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(
            line.starts_with("mock obs on "),
            "mock failed to start: {line}"
        );
        Self {
            child,
            endpoint: format!(
                "http://{}",
                line.trim().strip_prefix("mock obs on ").unwrap()
            ),
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

    pub fn stats(&self) -> String {
        reqwest::blocking::get(format!("{}/__stats", self.endpoint))
            .unwrap()
            .text()
            .unwrap()
    }
}

impl Drop for MockObs {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.staging);
    }
}
