use firmica_key_worker::{WorkerError, WorkerKey};
use secrecy::{SecretBox, SecretString};
use std::path::Path;

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platforms_reject_import_without_launching_a_worker() {
    assert_eq!(
        WorkerKey::import(
            Path::new(env!("CARGO_BIN_EXE_firmica-key-worker")),
            SecretBox::new(Box::new(vec![1])),
            SecretString::from("synthetic")
        )
        .err(),
        Some(WorkerError::UnsupportedPlatform)
    );
    assert!(firmica_key_worker::serve().is_err());
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use der::{Any, Decode, Encode, Sequence};
    use firmica_cades::{sign, ContentMode, SigningOptions};
    use firmica_certificates::{CertificateError, MAX_PKCS12_BYTES};
    use firmica_key_worker::{
        MAX_ADDRESS_SPACE_BYTES, MAX_CPU_SECONDS, MAX_PASSWORD_BYTES, MAX_SIGNING_INPUT_BYTES,
        OPERATION_TIMEOUT,
    };
    use firmica_signing::{SignatureAlgorithm, SigningError, SigningInput, SigningKey};
    use openssl::{
        asn1::{Asn1Integer, Asn1Time},
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkcs12::Pkcs12,
        pkey::PKey,
        rsa::Rsa,
        sha::sha256,
        x509::{extension::KeyUsage, X509Name, X509},
    };
    use std::{
        fs,
        io::Read,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
        time::{Instant, SystemTime},
    };

    const RSA: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15Sha256;
    const EC: SignatureAlgorithm = SignatureAlgorithm::EcdsaP256Sha256;
    const MESSAGE: &[u8] = b"Synthetic worker document\x00\xff\r\n";
    const PASSWORD: &str = "synthetic-only ü";

    fn executable() -> &'static Path {
        Path::new(env!("CARGO_BIN_EXE_firmica-key-worker"))
    }
    fn secret(bytes: Vec<u8>) -> SecretBox<Vec<u8>> {
        SecretBox::new(Box::new(bytes))
    }

    fn fixture(algorithm: SignatureAlgorithm) -> (Vec<u8>, X509) {
        let key = match algorithm {
            RSA => PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            EC => PKey::from_ec_key(
                EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
            )
            .unwrap(),
        };
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "Firmica synthetic worker")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(7).unwrap()).unwrap())
            .unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .append_extension(KeyUsage::new().digital_signature().build().unwrap())
            .unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = certificate.build();
        let mut additional = openssl::stack::Stack::new().unwrap();
        additional.push(certificate.clone()).unwrap();
        let container = Pkcs12::builder()
            .pkey(&key)
            .cert(&certificate)
            .ca(additional)
            .build2(PASSWORD)
            .unwrap()
            .to_der()
            .unwrap();
        (container, certificate)
    }

    fn cms_valid(certificate: &X509, encoded: &[u8], detached: Option<&[u8]>) -> bool {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("signature.der"), encoded).unwrap();
        fs::write(temp.path().join("trust.pem"), certificate.to_pem().unwrap()).unwrap();
        let mut command = Command::new("openssl");
        command.current_dir(temp.path()).args([
            "cms",
            "-verify",
            "-cades",
            "-binary",
            "-inform",
            "DER",
            "-in",
            "signature.der",
            "-CAfile",
            "trust.pem",
            "-no-CApath",
            "-no-CAstore",
            "-partial_chain",
            "-purpose",
            "any",
            "-out",
            "verified.bin",
        ]);
        if let Some(content) = detached {
            fs::write(temp.path().join("document.bin"), content).unwrap();
            command.args(["-content", "document.bin"]);
        }
        let output = command.output().expect("OpenSSL CLI is required");
        output.status.success() && fs::read(temp.path().join("verified.bin")).unwrap() == MESSAGE
    }

    #[test]
    fn imported_keys_sign_cades_and_digests_before_confirmed_close() {
        for algorithm in [RSA, EC] {
            let (container, certificate) = fixture(algorithm);
            let mut worker = WorkerKey::import(
                executable(),
                secret(container),
                SecretString::from(PASSWORD),
            )
            .unwrap();
            assert_eq!(
                worker.identity().certificate_der,
                certificate.to_der().unwrap()
            );
            assert_eq!(worker.capabilities().len(), 2);
            assert_eq!(
                worker.identity().additional_certificates,
                vec![certificate.to_der().unwrap()]
            );
            let other = if algorithm == RSA { EC } else { RSA };
            assert_eq!(
                worker.sign(other, SigningInput::Message(MESSAGE)).err(),
                Some(SigningError::UnsupportedOperation)
            );
            assert_eq!(
                worker
                    .sign(
                        algorithm,
                        SigningInput::Message(&vec![0; MAX_SIGNING_INPUT_BYTES + 1])
                    )
                    .err(),
                Some(SigningError::UnsupportedOperation)
            );
            let digest = sha256(MESSAGE);
            let primitive = worker
                .sign(algorithm, SigningInput::Sha256Digest(&digest))
                .unwrap();
            let mut produced = Vec::new();
            for mode in [ContentMode::Attached, ContentMode::Detached] {
                produced.push((
                    mode,
                    sign(
                        &mut worker,
                        MESSAGE,
                        SigningOptions {
                            algorithm,
                            mode,
                            signing_time: SystemTime::now(),
                        },
                    )
                    .unwrap(),
                ));
            }
            // Cleanup acknowledgement and successful child exit gate all consumption.
            worker.close().unwrap();
            let temp = tempfile::tempdir().unwrap();
            fs::write(
                temp.path().join("public.pem"),
                certificate
                    .public_key()
                    .unwrap()
                    .public_key_to_pem()
                    .unwrap(),
            )
            .unwrap();
            fs::write(temp.path().join("signature.bin"), primitive.value).unwrap();
            fs::write(temp.path().join("document.bin"), MESSAGE).unwrap();
            let verified = Command::new("openssl")
                .current_dir(temp.path())
                .args([
                    "dgst",
                    "-sha256",
                    "-verify",
                    "public.pem",
                    "-signature",
                    "signature.bin",
                    "document.bin",
                ])
                .output()
                .unwrap();
            assert!(verified.status.success());
            for (mode, encoded) in produced {
                assert!(cms_valid(
                    &certificate,
                    &encoded,
                    (mode == ContentMode::Detached).then_some(MESSAGE)
                ));
                assert!(!cms_valid(&certificate, &encoded, Some(b"modified")));
            }
        }
    }

    #[test]
    fn bad_inputs_and_import_errors_do_not_return_a_key() {
        for (bytes, password) in [
            (vec![], "".to_owned()),
            (vec![0; MAX_PKCS12_BYTES + 1], "".to_owned()),
            (vec![1], "NUL\0password".to_owned()),
            (vec![1], "x".repeat(MAX_PASSWORD_BYTES + 1)),
        ] {
            assert_eq!(
                WorkerKey::import(executable(), secret(bytes), SecretString::from(password)).err(),
                Some(WorkerError::InvalidInput)
            );
        }
        assert_eq!(
            WorkerKey::import(
                Path::new("relative-worker"),
                secret(vec![1]),
                SecretString::from("")
            )
            .err(),
            Some(WorkerError::InvalidInput)
        );
        assert_eq!(
            WorkerKey::import(
                Path::new("/nonexistent-firmica-worker"),
                secret(vec![1]),
                SecretString::from("")
            )
            .err(),
            Some(WorkerError::Unavailable)
        );
        assert_eq!(
            WorkerKey::import(
                executable(),
                secret(vec![1, 2]),
                SecretString::from(PASSWORD)
            )
            .err(),
            Some(WorkerError::Import(CertificateError::InvalidContainer))
        );
        let (container, _) = fixture(EC);
        assert_eq!(
            WorkerKey::import(
                executable(),
                secret(container),
                SecretString::from("wrong password")
            )
            .err(),
            Some(WorkerError::Import(CertificateError::UnlockFailed))
        );
    }

    fn quote(path: &Path) -> String {
        format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
    }
    fn launcher(directory: &Path, body: &str) -> std::path::PathBuf {
        let path = directory.join("worker");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s' \"$$\" > {}\n{body}\n",
                quote(&directory.join("pid"))
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    fn pid(directory: &Path) -> u32 {
        fs::read_to_string(directory.join("pid"))
            .unwrap()
            .parse()
            .unwrap()
    }
    fn gone(pid: u32) {
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "worker must be terminated and reaped"
        );
    }

    #[test]
    fn deadlines_cover_stalled_startup_and_blocked_pipe_writes() {
        for hello in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let prefix = if hello {
                "printf '\\000\\000\\000\\007FRMKEY\\001'\n"
            } else {
                ""
            };
            let launcher = launcher(directory.path(), &format!("{prefix}exec sleep 60"));
            let start = Instant::now();
            assert_eq!(
                WorkerKey::import(
                    &launcher,
                    secret(vec![0; MAX_PKCS12_BYTES]),
                    SecretString::from(PASSWORD)
                )
                .err(),
                Some(WorkerError::TimedOut)
            );
            assert!(start.elapsed() < OPERATION_TIMEOUT + std::time::Duration::from_secs(3));
            gone(pid(directory.path()));
        }
    }

    #[test]
    fn malformed_replies_fail_before_allocating_unbounded_output() {
        let directory = tempfile::tempdir().unwrap();
        let launcher = launcher(
            directory.path(),
            "printf '\\377\\377\\377\\377'\nexec sleep 60",
        );
        assert_eq!(
            WorkerKey::import(&launcher, secret(vec![1]), SecretString::from(PASSWORD)).err(),
            Some(WorkerError::Protocol)
        );
        gone(pid(directory.path()));
    }

    #[test]
    fn dropping_or_losing_a_worker_reaps_it_and_prevents_publication() {
        for killed in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let launcher = launcher(
                directory.path(),
                &format!("exec {} --stdio", quote(executable())),
            );
            let (container, _) = fixture(EC);
            let mut key =
                WorkerKey::import(&launcher, secret(container), SecretString::from(PASSWORD))
                    .unwrap();
            let pid = pid(directory.path());
            let args = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
            assert!(!String::from_utf8_lossy(&args).contains(PASSWORD));
            if killed {
                let _unpublished = key.sign(EC, SigningInput::Message(MESSAGE)).unwrap();
                rustix::process::kill_process(
                    rustix::process::Pid::from_raw(pid as i32).unwrap(),
                    rustix::process::Signal::KILL,
                )
                .unwrap();
                assert_eq!(
                    key.sign(EC, SigningInput::Message(MESSAGE)).err(),
                    Some(SigningError::BackendFailure)
                );
                assert_eq!(
                    key.sign(EC, SigningInput::Message(MESSAGE)).err(),
                    Some(SigningError::BackendFailure)
                );
                assert_eq!(key.close(), Err(WorkerError::Unavailable));
            } else {
                drop(key);
            }
            gone(pid);
        }
    }

    #[test]
    fn native_limits_are_installed_before_the_worker_accepts_credentials() {
        use rustix::process::{prlimit, Pid, Resource, Rlimit};
        let mut child = Command::new(executable())
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let output = child.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut output = output;
            let mut hello = [0; 11];
            let result = output.read_exact(&mut hello).map(|_| hello);
            let _ = send.send(result);
        });
        let hello = receive.recv_timeout(OPERATION_TIMEOUT);
        let limits = [
            (Resource::As, MAX_ADDRESS_SPACE_BYTES),
            (Resource::Cpu, MAX_CPU_SECONDS),
            (Resource::Core, 0),
        ]
        .map(|(resource, value)| {
            let expected = Rlimit {
                current: Some(value),
                maximum: Some(value),
            };
            (
                prlimit(Pid::from_raw(pid as i32), resource, expected),
                expected,
            )
        });
        // Cleanup even if a startup assertion would fail.
        child.kill().unwrap();
        child.wait().unwrap();
        reader.join().unwrap();
        assert_eq!(hello.unwrap().unwrap(), *b"\0\0\0\x07FRMKEY\x01");
        for (actual, expected) in limits {
            assert_eq!(actual.unwrap(), expected);
        }
        gone(pid);
    }

    #[derive(Sequence)]
    struct Pfx {
        version: u8,
        auth_safe: Any,
        mac: MacData,
    }
    #[derive(Sequence)]
    struct MacData {
        digest: Any,
        salt: der::asn1::OctetString,
        iterations: u32,
    }

    #[test]
    fn excessive_native_mac_kdf_work_is_terminated() {
        let (container, _) = fixture(EC);
        let mut pfx = Pfx::from_der(&container).unwrap();
        // The MAC value is unchanged: native verification must derive its key before
        // detecting the mismatch. Encoding this integer does not perform expensive work.
        pfx.mac.iterations = 1_000_000_000;
        let directory = tempfile::tempdir().unwrap();
        let launcher = launcher(
            directory.path(),
            &format!("exec {} --stdio", quote(executable())),
        );
        let start = Instant::now();
        assert!(matches!(
            WorkerKey::import(
                &launcher,
                secret(pfx.to_der().unwrap()),
                SecretString::from(PASSWORD)
            )
            .err(),
            Some(WorkerError::Unavailable | WorkerError::TimedOut)
        ));
        assert!(start.elapsed() < OPERATION_TIMEOUT + std::time::Duration::from_secs(3));
        gone(pid(directory.path()));
    }
}
