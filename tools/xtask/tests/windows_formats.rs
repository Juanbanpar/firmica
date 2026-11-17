mod signing_support;
mod support;
mod windows_signing_support;
#[cfg(windows)]
use std::{env, fs, path::PathBuf, process::Command};

#[cfg(windows)]
#[test]
#[ignore = "requires a disposable Windows desktop, extracted portable bundle, Firefox, Python UI tooling, OpenSSL, Poppler and XMLSec"]
fn extracted_bundle_signs_all_formats() {
    let app = PathBuf::from(env::var_os("FIRMICA_TEST_APP").expect("FIRMICA_TEST_APP"))
        .canonicalize()
        .unwrap();
    for (suite, driver, seconds) in [
        ("local", "windows-signing.py", 240),
        ("browser", "windows-browser.py", 900),
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let config = windows_signing_support::fixtures(temporary.path());
        let evidence = support::root().join(format!(".test-artifacts/windows-{suite}"));
        fs::create_dir_all(&evidence).unwrap();
        let result = support::output(
            Command::new("python")
                .arg("-u")
                .arg(support::root().join("tests/interop").join(driver))
                .arg("--app")
                .arg(&app)
                .arg("--fixtures")
                .arg(temporary.path())
                .arg("--output")
                .arg(&evidence),
            seconds,
        );
        fs::write(
            evidence.join("driver.log"),
            [result.stdout, result.stderr].concat(),
        )
        .unwrap();
        assert!(
            result.status.success(),
            "Windows {suite} UI failed; see {}",
            evidence.display()
        );
        windows_signing_support::verify(&config, suite, temporary.path(), &evidence);
    }
}
