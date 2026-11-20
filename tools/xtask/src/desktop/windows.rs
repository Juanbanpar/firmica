use super::*;
use std::io::{self, Read, Seek, SeekFrom};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

const BINARIES: [&str; 4] = [
    "firmica.exe",
    "firmica-key-worker.exe",
    "libcrypto-3-x64.dll",
    "libssl-3-x64.dll",
];
const NOTICES: [&str; 3] = ["handler.ps1", "LICENSE", "OpenSSL-LICENSE.txt"];

#[cfg(windows)]
pub(super) fn stage(
    root: &Path,
    target: &Path,
    triple: &str,
    application: &Path,
    bundle: bool,
) -> Result<()> {
    for (source, name) in [
        ("LICENSE", "LICENSE"),
        ("tools/windows/handler.ps1", "handler.ps1"),
    ] {
        fs::copy(root.join(source), application.join(name))?;
    }
    let openssl = PathBuf::from(env::var_os("OPENSSL_DIR").context("OPENSSL_DIR is required")?);
    for name in &BINARIES[2..] {
        let source = [openssl.join("bin").join(name), openssl.join(name)]
            .into_iter()
            .find(|path| path.is_file())
            .with_context(|| {
                format!(
                    "missing x64 OpenSSL runtime {name} under {}",
                    openssl.display()
                )
            })?;
        fs::copy(source, application.join(name))?;
    }
    let license = ["license.txt", "LICENSE.txt", "LICENSE"]
        .into_iter()
        .map(|name| openssl.join(name))
        .find(|path| path.is_file())
        .context("OpenSSL distribution license is missing")?;
    fs::copy(license, application.join("OpenSSL-LICENSE.txt"))?;
    for name in BINARIES {
        let path = application.join(name);
        validate_pe(&mut regular_file(&path)?, name.ends_with(".dll"))
            .with_context(|| format!("invalid Windows binary {}", path.display()))?;
    }
    if bundle {
        let directory = target.join("dx/firmica/bundle/windows");
        fs::create_dir_all(&directory)?;
        let archive = directory.join(format!("firmica-{triple}.zip"));
        archive_application(application, &archive)?;
        println!("{}", archive.display());
    }
    Ok(())
}

fn regular_file(path: &Path) -> Result<fs::File> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("reparse point in Windows package: {}", path.display());
        }
    }
    if !metadata.is_file() || metadata.len() == 0 {
        bail!("expected a nonempty regular file: {}", path.display());
    }
    Ok(fs::File::open(path)?)
}

fn validate_pe(file: &mut (impl Read + Seek), dll: bool) -> Result<()> {
    let mut dos = [0; 64];
    file.read_exact(&mut dos)?;
    let offset = u32::from_le_bytes(dos[60..64].try_into()?);
    if &dos[..2] != b"MZ" || offset < 64 {
        bail!("missing DOS header");
    }
    file.seek(SeekFrom::Start(offset.into()))?;
    let mut coff = [0; 26];
    file.read_exact(&mut coff)?;
    let characteristics = u16::from_le_bytes(coff[22..24].try_into()?);
    if &coff[..4] != b"PE\0\0"
        || u16::from_le_bytes(coff[4..6].try_into()?) != 0x8664
        || u16::from_le_bytes(coff[24..26].try_into()?) != 0x20b
        || characteristics & 0x0002 == 0
        || (characteristics & 0x2000 != 0) != dll
    {
        bail!("expected an x64 PE executable or DLL matching its package entry");
    }
    Ok(())
}

fn archive_application(application: &Path, destination: &Path) -> Result<()> {
    let style = stylesheet(&application.join("assets"))?;
    let name = style
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid stylesheet filename")?;
    let style = format!("assets/{name}");
    let files: Vec<_> = BINARIES
        .into_iter()
        .chain(NOTICES)
        .chain([style.as_str()])
        .collect();
    let directory = destination
        .parent()
        .context("missing ZIP output directory")?;
    let mut staged = tempfile::NamedTempFile::new_in(directory)?;
    let mut zip = ZipWriter::new(staged.as_file_mut());
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for name in &files {
        zip.start_file(*name, options)?;
        io::copy(&mut regular_file(&application.join(name))?, &mut zip)?;
    }
    zip.finish()?;

    let mut zip = ZipArchive::new(staged.reopen()?)?;
    if zip.len() != files.len() {
        bail!("unexpected number of entries in portable ZIP");
    }
    for name in files {
        io::copy(&mut zip.by_name(name)?, &mut io::sink())?;
    }
    drop(zip);
    staged.persist(destination)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn portable_zip_contains_only_the_runtime_payload() {
        let temp = tempfile::tempdir().unwrap();
        let application = temp.path().join("App space & 'apostrophe'");
        fs::create_dir_all(application.join("assets")).unwrap();
        for name in BINARIES.into_iter().chain(NOTICES).chain([
            "assets/tailwind-test.css",
            "firmica.pdb",
            "fixture.p12",
        ]) {
            fs::write(application.join(name), b"fixture").unwrap();
        }
        let archive = temp.path().join("portable.zip");
        archive_application(&application, &archive).unwrap();
        let zip = ZipArchive::new(fs::File::open(archive).unwrap()).unwrap();
        assert_eq!(
            zip.file_names()
                .map(|name| name.unwrap().into_owned())
                .collect::<std::collections::BTreeSet<_>>(),
            BINARIES
                .into_iter()
                .chain(NOTICES)
                .chain(["assets/tailwind-test.css"])
                .map(str::to_owned)
                .collect()
        );
        fs::remove_file(application.join("firmica-key-worker.exe")).unwrap();
        assert!(archive_application(&application, &temp.path().join("incomplete.zip")).is_err());
        assert!(!temp.path().join("incomplete.zip").exists());
    }

    #[test]
    fn binaries_must_be_x64_and_match_the_entry_type() {
        let mut bytes = [0; 90];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[86..88].copy_from_slice(&0x2002u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
        assert!(validate_pe(&mut Cursor::new(bytes), true).is_ok());
        assert!(validate_pe(&mut Cursor::new(bytes), false).is_err());
        bytes[68..70].copy_from_slice(&0xaa64u16.to_le_bytes());
        assert!(validate_pe(&mut Cursor::new(bytes), true).is_err());
    }
}
