//! Blocking local workflow. All calls that read files, import, sign or close a key
//! run outside the UI loop. Browser request parameters never enter this module.

use firmica_cades::{ContentMode, MAX_CONTENT_BYTES};
use firmica_core::signing::{ApprovalError, CadesReview};
use firmica_key_worker::{WorkerError, WorkerKey};
use firmica_signing::SignatureAlgorithm;
use secrecy::{ExposeSecretMut, SecretBox, SecretString};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

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
}

/// Resolve only beside the running application, including extracted packages.
/// A trusted installation must protect both executables from modification.
pub fn packaged_worker() -> Result<PathBuf, Error> {
    let application = std::env::current_exe().map_err(|_| Error::MissingWorker)?;
    let path = application
        .parent()
        .ok_or(Error::MissingWorker)?
        .join("firmica-key-worker");
    let metadata = path.symlink_metadata().map_err(|_| Error::MissingWorker)?;
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file()
        || metadata.mode() & 0o022 != 0
        || metadata.uid()
            != application
                .metadata()
                .map_err(|_| Error::MissingWorker)?
                .uid()
    {
        return Err(Error::MissingWorker);
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
        let container = read_bounded(container, MAX_CONTAINER_BYTES)?;
        let name = document
            .file_name()
            .ok_or(Error::ReadInput)?
            .to_string_lossy()
            .into_owned();
        let key = WorkerKey::import(executable, container, password).map_err(Error::Worker)?;
        let document = std::mem::take(content.expose_secret_mut());
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
    pub fn sign_and_save(mut self, path: &Path, cancelled: &AtomicBool) -> Result<(), Error> {
        let mut worker = self.worker.take().expect("live worker");
        let result = if cancelled.load(Ordering::Acquire) {
            Err(Error::Cancelled)
        } else {
            match path.try_exists() {
                Ok(true) => Err(Error::DestinationExists),
                Err(_) => Err(Error::Save),
                Ok(false) => self
                    .review
                    .take()
                    .expect("live review")
                    .approve()
                    .sign(&mut worker)
                    .map_err(Error::Approval),
            }
        };
        worker.close().map_err(Error::Worker)?;
        let signature = result?;
        if cancelled.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        save_new(path, &signature, cancelled)
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
    use rustix::fs::{open, Mode, OFlags};
    // O_NONBLOCK lets us reject pipes/devices after open without hanging on a FIFO.
    let mut file = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| Error::ReadInput)?,
    );
    let metadata = file.metadata().map_err(|_| Error::ReadInput)?;
    if !metadata.is_file() {
        return Err(Error::ReadInput);
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
    // Mode 0600, atomic publication, and no replacement of files or symlinks.
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
