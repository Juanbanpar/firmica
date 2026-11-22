use super::{
    review::{algorithm_name, hex},
    tr, BUTTON, FIELD,
};
use crate::signing::{
    native::{discover, NativeSource},
    Error,
};
use dioxus::prelude::*;
use firmica_providers::{Availability, CertificateCandidate, Error as ProviderError};
use firmica_signing::SignatureAlgorithm;
use firmica_validation::{assess_document_signing, CertificateAssessment};
use std::{collections::HashMap, time::SystemTime};

#[derive(Default)]
pub(super) struct Picker {
    source: Option<NativeSource>,
    generation: u64,
    entries: Vec<Entry>,
    selected: Option<usize>,
    load_error: Option<Error>,
}

struct Entry {
    candidate: CertificateCandidate,
    assessment: Option<CertificateAssessment>,
    duplicate: bool,
}

impl Entry {
    fn algorithm(&self) -> Option<SignatureAlgorithm> {
        if self.duplicate
            || !matches!(
                self.candidate.availability(),
                Availability::Available | Availability::Locked
            )
            || !self
                .assessment
                .as_ref()
                .is_some_and(CertificateAssessment::permits_local_signing)
        {
            return None;
        }
        self.candidate
            .capabilities()
            .first()
            .map(|capability| capability.algorithm)
    }

    fn label(&self, spanish: bool) -> String {
        let subject = self.assessment.as_ref().map_or_else(
            || tr(spanish, "Certificado ilegible", "Unreadable certificate"),
            CertificateAssessment::subject,
        );
        let status = if self.duplicate {
            tr(spanish, "selección ambigua", "ambiguous selection")
        } else if let Some(algorithm) = self.algorithm() {
            algorithm_name(algorithm)
        } else if self.candidate.availability() == Availability::PublicOnly {
            tr(spanish, "sin clave privada", "no private key")
        } else if self.candidate.capabilities().is_empty() {
            tr(
                spanish,
                "clave no disponible o incompatible",
                "key unavailable or unsupported",
            )
        } else {
            tr(spanish, "restricciones locales", "local restrictions")
        };
        format!(
            "{subject} · {status} · {}",
            hex(self.candidate.fingerprint())
        )
    }
}

impl Picker {
    pub(super) fn source(&self) -> Option<NativeSource> {
        self.source
    }

    pub(super) fn selected(
        &self,
    ) -> Option<(NativeSource, CertificateCandidate, SignatureAlgorithm)> {
        let entry = self.entries.get(self.selected?)?;
        Some((self.source?, entry.candidate.clone(), entry.algorithm()?))
    }

    pub(super) fn algorithm(&self) -> Option<SignatureAlgorithm> {
        self.entries.get(self.selected?)?.algorithm()
    }

    pub(super) fn clear_selection(&mut self) {
        self.selected = None;
    }

    fn select(&mut self, value: &str) {
        self.selected = value
            .split_once(':')
            .filter(|(generation, _)| generation.parse::<u64>() == Ok(self.generation))
            .and_then(|(_, index)| index.parse::<usize>().ok())
            .filter(|index| {
                self.entries
                    .get(*index)
                    .is_some_and(|entry| entry.algorithm().is_some())
            });
    }
}

pub(super) fn source_label(source: NativeSource, spanish: bool) -> &'static str {
    match source {
        #[cfg(windows)]
        NativeSource::CurrentUser => tr(
            spanish,
            "Windows · Usuario actual",
            "Windows · Current User",
        ),
        #[cfg(windows)]
        NativeSource::LocalMachine => {
            tr(spanish, "Windows · Equipo local", "Windows · Local Machine")
        }
        #[cfg(target_os = "macos")]
        NativeSource::Keychain => tr(spanish, "Llavero de macOS", "macOS Keychain"),
    }
}

fn source_value(source: NativeSource) -> &'static str {
    match source {
        #[cfg(windows)]
        NativeSource::CurrentUser => "user",
        #[cfg(windows)]
        NativeSource::LocalMachine => "machine",
        #[cfg(target_os = "macos")]
        NativeSource::Keychain => "keychain",
    }
}

#[component]
pub(super) fn CertificatePicker(
    mut picker: Signal<Picker>,
    busy: Signal<bool>,
    spanish: bool,
    on_change_source: EventHandler<()>,
) -> Element {
    let state = picker.read();
    let source = state.source;
    let generation = state.generation;
    let selected = state
        .selected
        .map(|index| format!("{generation}:{index}"))
        .unwrap_or_default();
    rsx! {
        label { class: "block", {tr(spanish, "Origen del certificado", "Certificate source")}
            select { id: "sign-certificate-source", class: FIELD, value: source.map_or("file", source_value), disabled: busy(),
                onchange: move |event| {
                    if busy() { return; }
                    let value = event.value();
                    let source = NativeSource::ALL.iter().copied()
                        .find(|source| source_value(*source) == value);
                    on_change_source.call(());
                    load(picker, busy, source);
                },
                option { value: "file", "PKCS#12 / PFX" }
                for source in NativeSource::ALL.iter().copied() {
                    option { key: "{source_value(source)}", value: source_value(source), {source_label(source, spanish)} }
                }
            }
        }
        if let Some(source) = source {
            label { class: "block", {tr(spanish, "Certificado", "Certificate")}
                select { id: "sign-native-certificate", class: FIELD, value: selected,
                    disabled: busy() || state.entries.is_empty(),
                    onchange: move |event| {
                        if !busy() { picker.write().select(&event.value()); }
                    },
                    option { value: "", {tr(spanish, "Selecciona un certificado", "Select a certificate")} }
                    for (index, entry) in state.entries.iter().enumerate() {
                        option { key: "{generation}:{index}", value: "{generation}:{index}",
                            disabled: entry.algorithm().is_none(),
                            {entry.label(spanish)}
                        }
                    }
                }
            }
            if let Some(entry) = state.selected.and_then(|index| state.entries.get(index)) {
                if let Some(assessment) = &entry.assessment {
                    dl { class: "grid grid-cols-1 gap-2 break-all sm:grid-cols-[10rem_1fr]",
                        dt { {tr(spanish, "Emisor declarado", "Claimed issuer")} }
                        dd { "{assessment.issuer()}" }
                        dt { {tr(spanish, "Huella SHA-256", "SHA-256 fingerprint")} }
                        dd { class: "font-mono text-xs", {hex(entry.candidate.fingerprint())} }
                    }
                }
                p { class: "text-sm", {tr(spanish,
                    "El sistema puede solicitar autorización al firmar.",
                    "The system may ask for authorization when you sign.")}
                }
            }
            if busy() && state.entries.is_empty() {
                p { role: "status", {tr(spanish, "Cargando certificados…", "Loading certificates…")} }
            } else if let Some(error) = &state.load_error {
                p { role: "alert",
                    if matches!(error, Error::Provider(ProviderError::AuthenticationRequired)) {
                        {tr(spanish, "Desbloquea el almacén de certificados y actualiza la lista.", "Unlock the certificate store and refresh the list.")}
                    } else {
                        {tr(spanish, "No se pudo leer el almacén de certificados.", "The certificate store could not be read.")}
                    }
                }
            } else if state.entries.iter().all(|entry| entry.algorithm().is_none()) {
                p { role: "status", {tr(spanish,
                    "No hay certificados disponibles para firmar en este almacén.",
                    "This store has no certificates available for signing.")}
                }
            }
            button { id: "sign-native-refresh", class: BUTTON, r#type: "button", disabled: busy(),
                onclick: move |_| { if !busy() { load(picker, busy, Some(source)); } },
                {tr(spanish, "Actualizar certificados", "Refresh certificates")}
            }
        }
    }
}

fn load(mut picker: Signal<Picker>, mut busy: Signal<bool>, source: Option<NativeSource>) {
    let generation = picker.peek().generation.wrapping_add(1);
    picker.set(Picker {
        source,
        generation,
        ..Default::default()
    });
    let Some(source) = source else {
        return;
    };
    busy.set(true);
    spawn(async move {
        let entries = tokio::task::spawn_blocking(move || {
            discover(source).map(|certificates| entries(certificates, SystemTime::now()))
        })
        .await;
        let mut state = picker.write();
        match entries {
            Ok(Ok(entries)) => state.entries = entries,
            Ok(Err(error)) => state.load_error = Some(error),
            Err(_) => state.load_error = Some(Error::Task),
        }
        drop(state);
        busy.set(false);
    });
}

fn entries(candidates: Vec<CertificateCandidate>, now: SystemTime) -> Vec<Entry> {
    let mut key_counts = HashMap::new();
    for candidate in &candidates {
        if !candidate.capabilities().is_empty() {
            *key_counts.entry(*candidate.fingerprint()).or_insert(0usize) += 1;
        }
    }
    candidates
        .into_iter()
        .map(|candidate| {
            let duplicate = key_counts
                .get(candidate.fingerprint())
                .is_some_and(|count| *count > 1);
            let assessment =
                assess_document_signing(&candidate.identity().certificate_der, now).ok();
            Entry {
                candidate,
                assessment,
                duplicate,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use firmica_providers::{Authentication, IdentityReference, ProviderId};
    use firmica_signing::{CertificateIdentity, InputKind, SigningCapability};
    use std::time::{Duration, UNIX_EPOCH};

    const CERTIFICATE: &[u8] =
        include_bytes!("../../../../../crates/core/src/signing/fixtures/document-signer.der");
    const ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15Sha256;

    fn candidate(key: u8, signable: bool) -> CertificateCandidate {
        CertificateCandidate::new(
            IdentityReference::new(ProviderId::new("synthetic"), vec![key]),
            CertificateIdentity {
                certificate_der: CERTIFICATE.to_vec(),
                additional_certificates: vec![],
            },
            if signable {
                vec![SigningCapability {
                    algorithm: ALGORITHM,
                    input: InputKind::Sha256Digest,
                }]
            } else {
                vec![]
            },
            if signable {
                Authentication::ProviderManaged
            } else {
                Authentication::None
            },
            if signable {
                Availability::Locked
            } else {
                Availability::PublicOnly
            },
        )
    }

    #[test]
    fn picker_rejects_previous_generations_and_public_only_rows() {
        let time = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut picker = Picker {
            source: Some(NativeSource::ALL[0]),
            generation: 2,
            entries: entries(vec![candidate(1, true), candidate(2, false)], time),
            ..Default::default()
        };
        picker.select("1:0");
        assert!(picker.selected().is_none());
        picker.select("2:1");
        assert!(picker.selected().is_none());
        picker.select("2:0");
        let (store, selected, algorithm) = picker.selected().unwrap();
        assert_eq!(store, NativeSource::ALL[0]);
        assert_eq!(selected.reference().key(), &[1]);
        assert_eq!(algorithm, ALGORITHM);
    }

    #[test]
    fn picker_rejects_indistinguishable_signing_rows() {
        let time = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut picker = Picker {
            source: Some(NativeSource::ALL[0]),
            entries: entries(vec![candidate(1, true), candidate(2, true)], time),
            ..Default::default()
        };
        picker.select("0:0");
        assert!(picker.selected().is_none());
        picker.select("0:1");
        assert!(picker.selected().is_none());
        assert!(picker.entries.iter().all(|entry| entry.duplicate));
    }
}
