//! Private Unix profile storage.
use super::*;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};

pub(super) fn config_base() -> Result<PathBuf, Error> {
    #[cfg(target_os = "macos")]
    {
        let home = PathBuf::from(std::env::var_os("HOME").ok_or(Error::Directory)?);
        if !home.is_absolute() {
            return Err(Error::Directory);
        }
        Ok(home.join("Library/Application Support"))
    }
    #[cfg(target_os = "linux")]
    config_home(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

#[cfg(target_os = "linux")]
pub(super) fn config_home(
    xdg: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf, Error> {
    let directory = match xdg.filter(|value| !value.is_empty()) {
        Some(value) => PathBuf::from(value),
        None => PathBuf::from(home.ok_or(Error::Directory)?).join(".config"),
    };
    if !directory.is_absolute() {
        return Err(Error::Directory);
    }
    Ok(directory)
}

pub(super) fn check_directory(path: &Path, private: bool) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path)?;
    let forbidden = if private { 0o077 } else { 0o022 };
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & forbidden != 0
    {
        return Err(Error::Permissions);
    }
    #[cfg(target_os = "macos")]
    if private {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::DIRECTORY).bits() as i32,
            )
            .open(path)?;
        crate::private_fs::ensure_no_acl(&directory).map_err(|_| Error::Permissions)?;
    }
    Ok(())
}

pub(super) fn read_private(path: &Path) -> Result<SecretBox<Vec<u8>>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error::Permissions);
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(Error::Invalid);
    }
    #[cfg(target_os = "macos")]
    crate::private_fs::ensure_no_acl(&file).map_err(|_| Error::Permissions)?;
    let mut bytes = SecretBox::new(Box::new(Vec::new()));
    use secrecy::ExposeSecretMut;
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(bytes.expose_secret_mut())?;
    if bytes.expose_secret().len() as u64 > MAX_FILE_BYTES {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    #[cfg(target_os = "macos")]
    crate::private_fs::ensure_no_acl(&file).map_err(|_| Error::Permissions)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn prepare(base: &Path) -> Result<PathBuf, Error> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(base)?;
    check_directory(base, false)?;
    let parent = base.join(PROFILE_PARENT);
    match fs::DirBuilder::new().mode(0o700).create(&parent) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    check_directory(&parent, true)?;
    Ok(parent)
}

pub(super) fn staging(parent: &Path) -> Result<tempfile::TempDir, Error> {
    Ok(tempfile::Builder::new()
        .prefix(".browser-tls-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?)
}

pub(super) fn publish(staging: &Path, destination: &Path) -> Result<(), Error> {
    File::open(staging)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| match error {
        rustix::io::Errno::EXIST | rustix::io::Errno::NOTEMPTY => Error::Exists,
        error => Error::Io(error.into()),
    })?;
    File::open(destination.parent().ok_or(Error::Directory)?)?.sync_all()?;
    Ok(())
}
