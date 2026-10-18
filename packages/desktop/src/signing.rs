//! Blocking local workflow. All calls that read files, import, sign or close a key
//! run outside the UI loop. Browser data must first pass operation-specific decoding.

use firmica_cades::{ContentMode, MAX_CONTENT_BYTES};
use firmica_core::signing::{ApprovalError, CadesReview};
use firmica_key_worker::{WorkerError, WorkerKey};
use firmica_protocol::signing::SignResponse;
use firmica_signing::{SignatureAlgorithm, SigningKey};
use secrecy::{ExposeSecretMut, SecretBox, SecretString};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(target_os = "linux")]
use std::fs::File;

const MAX_CONTAINER_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    ReadInput,
    InputTooLarge,
    MissingWorker,
    Worker(WorkerError),
    Approval(ApprovalError),
    Save,
    DestinationExists,
    Cancelled,
    Task,
    Response,
}

/// Resolve only beside the running application, including extracted packages.
/// A trusted installation must protect both executables from modification.
pub fn packaged_worker() -> Result<PathBuf, Error> {
    let application = std::env::current_exe().map_err(|_| Error::MissingWorker)?;
    worker_beside(&application)
}

fn worker_beside(application: &Path) -> Result<PathBuf, Error> {
    let path = application
        .parent()
        .ok_or(Error::MissingWorker)?
        .join(if cfg!(windows) {
            "firmica-key-worker.exe"
        } else {
            "firmica-key-worker"
        });
    let metadata = path.symlink_metadata().map_err(|_| Error::MissingWorker)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::MissingWorker);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0
            || metadata.uid()
                != application
                    .metadata()
                    .map_err(|_| Error::MissingWorker)?
                    .uid()
        {
            return Err(Error::MissingWorker);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::MissingWorker);
        }
    }
    Ok(path)
}

/// Opaque, single-use imported key and frozen review. No Clone/Debug implementation.
pub struct Prepared {
    worker: Option<WorkerKey>,
    review: Option<CadesReview>,
}

impl Prepared {
    pub fn open(
        executable: &Path,
        document: &Path,
        container: &Path,
        password: SecretString,
        algorithm: SignatureAlgorithm,
        mode: ContentMode,
    ) -> Result<Self, Error> {
        let mut content = read_bounded(document, MAX_CONTENT_BYTES)?;
        let name = document
            .file_name()
            .ok_or(Error::ReadInput)?
            .to_string_lossy()
            .into_owned();
        let document = std::mem::take(content.expose_secret_mut());
        Self::open_document(
            executable, name, document, container, password, algorithm, mode,
        )
    }

    /// Imports only a user-selected container. Document bytes and choices have
    /// already been decoded from the bounded request, never from a URL or path.
    pub fn open_document(
        executable: &Path,
        name: String,
        document: Vec<u8>,
        container: &Path,
        password: SecretString,
        algorithm: SignatureAlgorithm,
        mode: ContentMode,
    ) -> Result<Self, Error> {
        if document.len() > MAX_CONTENT_BYTES {
            return Err(Error::InputTooLarge);
        }
        let container = read_bounded(container, MAX_CONTAINER_BYTES)?;
        let key = WorkerKey::import(executable, container, password).map_err(Error::Worker)?;
        match CadesReview::prepare(name, document, &key, algorithm, mode) {
            Ok(review) => Ok(Self {
                worker: Some(key),
                review: Some(review),
            }),
            Err(error) => {
                key.close().map_err(Error::Worker)?;
                Err(Error::Approval(error))
            }
        }
    }

    pub fn review(&self) -> &CadesReview {
        self.review.as_ref().expect("live review")
    }

    /// Explicit cancellation confirms cleanup without calling the private key.
    pub fn cancel(mut self) -> Result<(), Error> {
        self.review.take();
        self.worker
            .take()
            .expect("live worker")
            .close()
            .map_err(Error::Worker)
    }

    /// Called only after explicit UI approval and destination selection. Cleanup
    /// failure takes precedence over signing failure; no output is published then.
    pub fn sign_and_save(self, path: &Path, cancelled: &AtomicBool) -> Result<(), Error> {
        let destination = match path.try_exists() {
            Ok(true) => Err(Error::DestinationExists),
            Err(_) => Err(Error::Save),
            Ok(false) => Ok(()),
        };
        if let Err(error) = destination {
            self.cancel()?;
            return Err(error);
        }
        let (_, signature) = self.sign_bytes(cancelled)?;
        save_new(path, &signature, cancelled)
    }

    /// Releases a bounded protocol response only after signing and confirmed
    /// worker cleanup. The caller must deliver it only to the original live reply.
    pub fn sign_for_browser(self, cancelled: &AtomicBool) -> Result<SignResponse, Error> {
        let (certificate, signature) = self.sign_bytes(cancelled)?;
        SignResponse::new(&certificate, &signature).map_err(|_| Error::Response)
    }

    fn sign_bytes(mut self, cancelled: &AtomicBool) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut worker = self.worker.take().expect("live worker");
        let certificate = worker.identity().certificate_der.clone();
        let result = if cancelled.load(Ordering::Acquire) {
            Err(Error::Cancelled)
        } else {
            self.review
                .take()
                .expect("live review")
                .approve()
                .sign(&mut worker)
                .map_err(Error::Approval)
        };
        worker.close().map_err(Error::Worker)?;
        let signature = result?;
        if cancelled.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        Ok((certificate, signature))
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            // Unmounting a component or abandoning an async task must not perform
            // blocking process I/O on the UI loop. No signature is published here.
            let _ = std::thread::Builder::new().spawn(move || {
                let _ = worker.close();
            });
        }
    }
}

fn read_bounded(path: &Path, limit: usize) -> Result<SecretBox<Vec<u8>>, Error> {
    #[cfg(target_os = "linux")]
    use rustix::fs::{open, Mode, OFlags};
    // O_NONBLOCK lets us reject pipes/devices after open without hanging on a FIFO.
    #[cfg(target_os = "linux")]
    let mut file = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| Error::ReadInput)?,
    );
    #[cfg(windows)]
    let mut file = {
        use std::os::windows::fs::OpenOptionsExt;
        use std::path::{Component, Prefix};
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        // Exclude device and named-pipe namespaces before opening: they are not
        // documents and opening a pipe can block before metadata is available.
        let Some(Component::Prefix(prefix)) = path.components().next() else {
            return Err(Error::ReadInput);
        };
        let disk_path = match prefix.kind() {
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) => path.is_absolute(),
            Prefix::UNC(_, share) | Prefix::VerbatimUNC(_, share) => {
                !share.to_string_lossy().eq_ignore_ascii_case("pipe$")
                    && !share.to_string_lossy().eq_ignore_ascii_case("pipe")
            }
            _ => false,
        };
        if !disk_path {
            return Err(Error::ReadInput);
        }
        // Open the entry itself so a file reparse point cannot redirect the read.
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| Error::ReadInput)?
    };
    let metadata = file.metadata().map_err(|_| Error::ReadInput)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::ReadInput);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::ReadInput);
        }
    }
    if metadata.len() > limit as u64 {
        return Err(Error::InputTooLarge);
    }
    // Allocate before reading to avoid reallocations copying encrypted key material.
    let mut bytes = SecretBox::new(Box::new(vec![0; limit + 1]));
    let mut length = 0;
    loop {
        match file.read(&mut bytes.expose_secret_mut()[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::ReadInput),
        }
        if length > limit {
            return Err(Error::InputTooLarge);
        }
    }
    bytes.expose_secret_mut().truncate(length);
    Ok(bytes)
}

fn save_new(path: &Path, signature: &[u8], cancelled: &AtomicBool) -> Result<(), Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| Error::Save)?;
    temporary.write_all(signature).map_err(|_| Error::Save)?;
    temporary.as_file().sync_all().map_err(|_| Error::Save)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(Error::Cancelled);
    }
    // No replacement of files or symlinks. Unix uses mode 0600; Windows
    // inherits the destination directory ACL, so use a trusted directory.
    temporary.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::DestinationExists
        } else {
            Error::Save
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
