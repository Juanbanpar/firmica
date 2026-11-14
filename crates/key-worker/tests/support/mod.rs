use std::{path::Path, path::PathBuf, process::Command, sync::OnceLock};

/// Build once and use Cargo's artifact report; intermediate paths are unstable.
pub(crate) fn worker_fixture() -> &'static Path {
    static EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();
    EXECUTABLE.get_or_init(|| {
        let output = Command::new(env!("CARGO"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args([
                "build",
                "--locked",
                "--package",
                "firmica-key-worker",
                "--example",
                "worker-fixture",
                "--message-format=json",
            ])
            .output()
            .expect("cannot build the worker fixture");
        assert!(
            output.status.success(),
            "worker fixture build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find_map(|message| {
                (message["reason"] == "compiler-artifact"
                    && message["target"]["name"] == "worker-fixture")
                    .then(|| message["executable"].as_str().map(PathBuf::from))
                    .flatten()
            })
            .expect("Cargo did not report the worker fixture executable")
    })
}
