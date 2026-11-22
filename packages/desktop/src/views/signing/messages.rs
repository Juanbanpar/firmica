use crate::signing::Error;
use firmica_core::signing::ApprovalError;
use firmica_providers::{pkcs12::WorkerError, Error as ProviderError};
use firmica_validation::Restriction;

pub(super) fn tr(es: bool, spanish: &'static str, english: &'static str) -> &'static str {
    if es {
        spanish
    } else {
        english
    }
}

pub(super) enum Status {
    Idle,
    Opening,
    Ready,
    ChoosingDestination,
    Signing,
    Cancelling,
    Cancelled,
    Saved,
    Failed(Error),
}

impl Status {
    pub(super) fn text(&self, external: bool, spanish: bool) -> String {
        match self {
            Self::Idle => if external {
                tr(
                    spanish,
                    "Selecciona un certificado PKCS#12 para revisar la solicitud.",
                    "Choose a PKCS#12 certificate to review the request.",
                )
            } else {
                tr(
                    spanish,
                    "Selecciona un documento y un certificado PKCS#12.",
                    "Choose a document and a PKCS#12 certificate.",
                )
            }
            .to_owned(),
            Self::Opening => tr(
                spanish,
                "Abriendo el certificado…",
                "Opening the certificate…",
            )
            .to_owned(),
            Self::Ready => tr(
                spanish,
                "Revisa los datos antes de autorizar la firma.",
                "Review the details before authorizing signing.",
            )
            .to_owned(),
            Self::ChoosingDestination => tr(
                spanish,
                "Elige dónde guardar la firma.",
                "Choose where to save the signature.",
            )
            .to_owned(),
            Self::Signing if external => tr(
                spanish,
                "Firmando para el navegador…",
                "Signing for the browser…",
            )
            .to_owned(),
            Self::Signing => tr(spanish, "Firmando y guardando…", "Signing and saving…").to_owned(),
            Self::Cancelling => tr(spanish, "Cancelando…", "Cancelling…").to_owned(),
            Self::Cancelled => {
                tr(spanish, "Operación cancelada.", "Operation cancelled.").to_owned()
            }
            Self::Saved => tr(spanish, "Firma guardada.", "Signature saved.").to_owned(),
            Self::Failed(error) => error_text(error, spanish),
        }
    }
}

fn error_text(error: &Error, es: bool) -> String {
    match error {
        Error::ReadInput => tr(es, "No se puede leer el archivo seleccionado. Debe ser un archivo normal.", "Cannot read the selected file. It must be a regular file."),
        Error::InputTooLarge => tr(es, "El archivo supera el límite indicado.", "The file exceeds the displayed size limit."),
        Error::MissingWorker => tr(es, "Falta el componente de certificados. Revisa la instalación de Firmica.", "The certificate worker is missing or unprotected. Check the Firmica installation."),
        Error::Provider(ProviderError::Worker(WorkerError::Import(_))) => tr(es, "No se puede abrir el certificado. Revisa el archivo y la contraseña.", "Cannot open the certificate. Check the file and password."),
        Error::Provider(ProviderError::AuthenticationRequired) => tr(es, "Desbloquea el almacén de certificados y vuelve a intentarlo.", "Unlock the certificate store and try again."),
        Error::Provider(ProviderError::StaleIdentity) => tr(es, "El certificado seleccionado ha cambiado o ha desaparecido. Actualiza la lista y vuelve a seleccionarlo.", "The selected certificate changed or disappeared. Refresh the list and select it again."),
        Error::Provider(_) => tr(es, "No se pudo completar la operación de certificados de forma segura. No se ha guardado ninguna firma.", "The certificate operation could not complete safely. No signature was saved."),
        Error::Approval(ApprovalError::CertificateRestricted(restrictions)) => {
            return format!("{} {}", tr(es, "Firma bloqueada:", "Signing blocked:"), restrictions.iter().map(|restriction| restriction_text(*restriction, es)).collect::<Vec<_>>().join("; "));
        }
        Error::Approval(ApprovalError::UnsupportedAlgorithm) => tr(es, "El certificado no admite el algoritmo elegido.", "The certificate does not support the chosen algorithm."),
        Error::Approval(ApprovalError::Pades(_)) => tr(es, "No se puede firmar este PDF o su apariencia. No se admiten PDF cifrados, certificados, bloqueados ni XFA. Comprueba la página y las coordenadas.", "Cannot sign this PDF or appearance. Encrypted, certified, locked and XFA PDFs are unsupported. Check the page and coordinates."),
        Error::Approval(ApprovalError::Xades(_)) => tr(es, "No se puede firmar este XML. Revisa el formato; no se admiten DTD, identificadores duplicados ni firmas XML previas.", "Cannot sign this XML. Check the format; DTDs, duplicate IDs and existing XML signatures are unsupported."),
        Error::Approval(_) => tr(es, "No se pudo completar la firma. No se ha guardado ningún resultado.", "Signing failed. No result was saved."),
        Error::DestinationExists => tr(es, "El destino ya existe. No se ha reemplazado.", "The destination already exists. It was not replaced."),
        Error::Save => tr(es, "No se pudo guardar la firma. Comprueba el directorio de destino.", "Cannot save the signature. Check the destination directory."),
        Error::Cancelled => tr(es, "Operación cancelada.", "Operation cancelled."),
        Error::Response => tr(es, "El resultado supera el límite del protocolo. No se ha enviado.", "The result exceeds the protocol limit. It was not sent."),
        Error::Task => tr(es, "La operación se interrumpió. No se ha confirmado una firma guardada.", "The operation was interrupted. A saved signature has not been confirmed."),
    }.to_owned()
}

fn restriction_text(restriction: Restriction, es: bool) -> &'static str {
    match restriction {
        Restriction::NotYetValid => tr(
            es,
            "el certificado aún no es válido",
            "certificate is not yet valid",
        ),
        Restriction::Expired => tr(es, "el certificado ha caducado", "certificate has expired"),
        Restriction::CertificateAuthority => tr(
            es,
            "no se permiten claves de autoridad certificadora",
            "CA keys are not permitted",
        ),
        Restriction::KeyUsage => tr(
            es,
            "el uso de clave no permite firmar documentos",
            "key usage prohibits document signing",
        ),
        Restriction::ExtendedKeyUsage => tr(
            es,
            "el uso extendido no permite firmar documentos",
            "extended key usage prohibits document signing",
        ),
        Restriction::UnhandledCriticalExtension => tr(
            es,
            "extensión crítica sin procesar",
            "unhandled critical extension",
        ),
        Restriction::PrivateKeyNotYetValid => tr(
            es,
            "el periodo de uso de la clave privada aún no ha comenzado",
            "private-key usage period has not begun",
        ),
        Restriction::PrivateKeyExpired => tr(
            es,
            "el periodo de uso de la clave privada ha terminado",
            "private-key usage period has ended",
        ),
    }
}
