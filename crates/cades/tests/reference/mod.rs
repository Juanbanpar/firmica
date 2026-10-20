//! Test-only reference jars, pinned independently of Cargo dependencies.
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path, time::Duration};

const ARTIFACTS: &[(&str, &str)] = &[
    (
        "es/gob/afirma/afirma-core/1.9.1/afirma-core-1.9.1.jar",
        "1e2af31ff1962ccccfd35568b154262a8e632558695412e0e95e076c3eb4be2b",
    ),
    (
        "es/gob/afirma/afirma-crypto-core-pkcs7/1.9.1/afirma-crypto-core-pkcs7-1.9.1.jar",
        "57a4161b3edf0adc48814803771ffadcdb05c625691436191bfd4433bf70b89d",
    ),
    (
        "es/gob/afirma/afirma-crypto-core-pkcs7-tsp/1.9.1/afirma-crypto-core-pkcs7-tsp-1.9.1.jar",
        "6a633a059d18dfedaf0dadd61fc589c305f4a3aabbb26d7bca8c8e6b58f62df9",
    ),
    (
        "es/gob/afirma/afirma-crypto-cades/1.9.1/afirma-crypto-cades-1.9.1.jar",
        "04e290bb597688b7091578f38f9e9705a094c460f2d920d2ae3d262cefd3456a",
    ),
    (
        "es/gob/afirma/lib/afirma-lib-jmimemagic/0.0.10/afirma-lib-jmimemagic-0.0.10.jar",
        "878e4e8a55130d7d03052f79baa51b270daf664b5a4fddbd4c760634041bd046",
    ),
    (
        "com/madgag/spongycastle/core/1.58.0.0/core-1.58.0.0.jar",
        "199617dd5698c5a9312b898c0a4cec7ce9dd8649d07f65d91629f58229d72728",
    ),
    (
        "com/madgag/spongycastle/prov/1.58.0.0/prov-1.58.0.0.jar",
        "092fd09e7006b0814980513b013d4c2b3ffd24a49a635ab4b2d204bb51af1727",
    ),
    (
        "com/madgag/spongycastle/bcpkix-jdk15on/1.58.0.0/bcpkix-jdk15on-1.58.0.0.jar",
        "89b776cc46caf6f9c29de3fdfe3aad06313b05646778a60873fcfd41f09a87ce",
    ),
];

pub fn classpath() -> std::ffi::OsString {
    let cache =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.test-artifacts/cades-reference/lib");
    fs::create_dir_all(&cache).unwrap();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let mut jars = Vec::new();
    for &(artifact, expected) in ARTIFACTS {
        let destination = cache.join(artifact.rsplit('/').next().unwrap());
        let cached = destination.exists();
        let bytes = if cached {
            fs::read(&destination).unwrap()
        } else {
            let url = format!("https://repo.maven.apache.org/maven2/{artifact}");
            let mut bytes = Vec::new();
            client
                .get(url)
                .send()
                .unwrap()
                .error_for_status()
                .unwrap()
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .unwrap();
            bytes
        };
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            expected,
            "reference artifact checksum mismatch: {}",
            destination.display()
        );
        if !cached {
            fs::write(&destination, bytes).unwrap();
        }
        jars.push(destination);
    }
    // Enumerate only verified jars; unrelated cache entries cannot enter the classpath.
    std::env::join_paths(jars).unwrap()
}
