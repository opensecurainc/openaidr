//! Stage macOS sensor support files before publishing either executable alias.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

const PREFIX: &[u8] = b"pyi-contents-directory openaidr-runtime-";
const MANIFEST: &str = "runtime.json";
const LIMIT: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u64,
    name: String,
    entries: BTreeMap<String, Entry>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum Entry {
    File { sha256: String },
    Directory {},
    Symlink { target: String },
}

pub(crate) struct Runtime {
    directory: PathBuf,
    manifest: Manifest,
    manifest_bytes: Vec<u8>,
}

fn invalid() -> String {
    "The sensor runtime is missing or invalid. Existing executables were kept.".into()
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn name(bytes: &[u8]) -> Result<Option<String>, String> {
    let mut matches = bytes.windows(PREFIX.len()).enumerate()
        .filter(|(_, window)| *window == PREFIX);
    let Some((offset, _)) = matches.next() else { return Ok(None); };
    if matches.next().is_some() { return Err(invalid()); }
    let suffix = bytes.get(offset + PREFIX.len()..offset + PREFIX.len() + 65).ok_or_else(invalid)?;
    let digest = std::str::from_utf8(&suffix[..64]).map_err(|_| invalid())?;
    if suffix[64] != 0 || !hex_digest(digest) { return Err(invalid()); }
    Ok(Some(format!("openaidr-runtime-{digest}")))
}

fn real_directory(path: &Path) -> Result<(), String> {
    if !fs::symlink_metadata(path).map_err(|_| invalid())?.is_dir() { return Err(invalid()); }
    Ok(())
}

fn relative_path(value: &str) -> bool {
    !value.contains(['\\', '\0'])
        && value.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}

fn read_manifest(directory: &Path, expected: &str) -> Result<(Manifest, Vec<u8>), String> {
    real_directory(directory)?;
    let path = directory.join(MANIFEST);
    if !fs::symlink_metadata(&path).map_err(|_| invalid())?.is_file() { return Err(invalid()); }
    let mut bytes = Vec::new();
    fs::File::open(path).map_err(|_| invalid())?.take(LIMIT + 1)
        .read_to_end(&mut bytes).map_err(|_| invalid())?;
    if bytes.len() as u64 > LIMIT { return Err(invalid()); }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if manifest.schema != 1 || manifest.name != expected || manifest.entries.len() > 10000
        || manifest.entries.is_empty() {
        return Err(invalid());
    }
    for (path, entry) in &manifest.entries {
        if !relative_path(path) || path == MANIFEST { return Err(invalid()); }
        if let Entry::File { sha256 } = entry {
            if !hex_digest(sha256) { return Err(invalid()); }
        }
    }
    Ok((manifest, bytes))
}

fn validate(directory: &Path, manifest: &Manifest) -> Result<(), String> {
    real_directory(directory)?;
    let root = fs::canonicalize(directory).map_err(|_| invalid())?;
    let mut pending = vec![directory.to_path_buf()];
    let mut count = 0;
    while let Some(parent) = pending.pop() {
        for item in fs::read_dir(parent).map_err(|_| invalid())? {
            let path = item.map_err(|_| invalid())?.path();
            let relative = path.strip_prefix(directory).map_err(|_| invalid())?
                .to_str().ok_or_else(invalid)?;
            if relative == MANIFEST { continue; }
            let entry = manifest.entries.get(relative).ok_or_else(invalid)?;
            count += 1;
            let metadata = fs::symlink_metadata(&path).map_err(|_| invalid())?;
            match entry {
                Entry::File { sha256 } if metadata.is_file() => {
                    let mut file = fs::File::open(&path).map_err(|_| invalid())?;
                    let mut digest = Sha256::new();
                    std::io::copy(&mut file, &mut digest).map_err(|_| invalid())?;
                    if format!("{:x}", digest.finalize()) != *sha256 { return Err(invalid()); }
                }
                Entry::Directory {} if metadata.is_dir() => pending.push(path),
                Entry::Symlink { target } if metadata.file_type().is_symlink() => {
                    let target_path = Path::new(target);
                    let mut depth = relative.split('/').count() - 1;
                    for part in target.split('/') {
                        if part == ".." {
                            depth = depth.checked_sub(1).ok_or_else(invalid)?;
                        } else if !part.is_empty() && part != "." {
                            depth += 1;
                        }
                    }
                    if target.is_empty() || target.contains(['\\', '\0']) || target_path.is_absolute()
                        || fs::read_link(&path).map_err(|_| invalid())? != target_path
                        || !fs::canonicalize(&path).map_err(|_| invalid())?.starts_with(&root) {
                        return Err(invalid());
                    }
                }
                _ => return Err(invalid()),
            }
        }
    }
    if count != manifest.entries.len() { return Err(invalid()); }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn fixture(parent: &Path, identity: char, timestamp: u64) -> PathBuf {
        fs::create_dir_all(parent).unwrap();
        let name = format!("openaidr-runtime-{}", identity.to_string().repeat(64));
        let directory = parent.join(&name);
        fs::create_dir_all(directory.join("Python.framework/Versions/3.14")).unwrap();
        let payload = format!("runtime {identity}");
        fs::write(directory.join("Python.framework/Versions/3.14/Python"), &payload).unwrap();
        fs::set_permissions(directory.join("Python.framework/Versions/3.14/Python"),
            fs::Permissions::from_mode(0o755)).unwrap();
        symlink("3.14", directory.join("Python.framework/Versions/Current")).unwrap();
        symlink("Python.framework/Versions/Current/Python", directory.join("Python")).unwrap();
        let manifest = json!({"schema":1,"name":name,"entries":{
            "Python.framework":{"kind":"directory"},
            "Python.framework/Versions":{"kind":"directory"},
            "Python.framework/Versions/3.14":{"kind":"directory"},
            "Python.framework/Versions/3.14/Python":{"kind":"file","sha256":format!("{:x}",Sha256::digest(payload.as_bytes()))},
            "Python.framework/Versions/Current":{"kind":"symlink","target":"3.14"},
            "Python":{"kind":"symlink","target":"Python.framework/Versions/Current/Python"}
        }});
        fs::write(directory.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        let commit = identity.to_string().repeat(40);
        let version = format!("2026.10.8+{}", &commit[..7]);
        let build = json!({"version":version,"source_commit":commit,"source_timestamp":timestamp,
            "published_at":null,"publication_timestamp":null});
        let executable = parent.join("openaidr");
        fs::write(&executable, format!("#!/bin/sh\nif [ \"$1\" = build-info ]; then printf '%s\\n' '{build}'; else printf 'openaidr {version}\\n'; fi\n# pyi-contents-directory {name}\0\n")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        executable
    }

    #[test]
    fn validates_app_layout_and_runtime_inventory_before_copying() {
        let scratch = tempfile::tempdir().unwrap();
        let source = fixture(&scratch.path().join("source"), 'a', 1);
        let bytes = fs::read(&source).unwrap();
        let runtime = Runtime::inspect(&source, &bytes).unwrap().unwrap();
        let target = scratch.path().join("bin");
        fs::create_dir(&target).unwrap();
        runtime.stage(&target).unwrap();
        let installed = target.join(&runtime.manifest.name);
        assert_eq!(fs::read_link(installed.join("Python.framework/Versions/Current")).unwrap(), Path::new("3.14"));
        assert_eq!(fs::metadata(installed.join("Python")).unwrap().permissions().mode() & 0o777, 0o755);
        runtime.stage(&target).unwrap();
        let modified = fs::metadata(installed.join("Python")).unwrap().modified().unwrap();
        fs::write(installed.join("Python"), "runtime z").unwrap();
        fs::OpenOptions::new().write(true).open(installed.join("Python")).unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified)).unwrap();
        assert_eq!(fs::metadata(installed.join("Python")).unwrap().modified().unwrap(), modified);
        assert!(runtime.stage(&target).is_err());
        assert_eq!(fs::read_to_string(installed.join("Python")).unwrap(), "runtime z");

        let contents = scratch.path().join("OpenAIDR.app/Contents");
        fs::create_dir_all(contents.join("MacOS")).unwrap();
        fs::create_dir(contents.join("Resources")).unwrap();
        let bundled = contents.join("MacOS/openaidr");
        fs::rename(&source, &bundled).unwrap();
        fs::rename(&runtime.directory, contents.join("Resources").join(&runtime.manifest.name)).unwrap();
        symlink(Path::new("Resources").join(&runtime.manifest.name), contents.join("Frameworks")).unwrap();
        let runtime = Runtime::inspect(&bundled, &bytes).unwrap().unwrap();
        fs::remove_file(contents.join("Frameworks")).unwrap();
        symlink(&runtime.directory, contents.join("Frameworks")).unwrap();
        assert!(Runtime::inspect(&bundled, &bytes).is_err());
        fs::remove_file(contents.join("Frameworks")).unwrap();
        symlink(Path::new("Resources").join(&runtime.manifest.name), contents.join("Frameworks")).unwrap();

        let manifest_path = runtime.directory.join(MANIFEST);
        let original = runtime.manifest_bytes;
        let mut invalid_directory: serde_json::Value = serde_json::from_slice(&original).unwrap();
        invalid_directory["entries"]["Python.framework"]["unexpected"] = json!(true);
        for invalid_bytes in [b"{}".to_vec(), vec![b' '; LIMIT as usize + 1], serde_json::to_vec(&invalid_directory).unwrap()] {
            fs::write(&manifest_path, invalid_bytes).unwrap();
            assert!(Runtime::inspect(&bundled, &bytes).is_err());
        }
        fs::write(&manifest_path, &original).unwrap();
        fs::write(runtime.directory.join("unexpected"), "extra").unwrap();
        assert!(Runtime::inspect(&bundled, &bytes).is_err());
        fs::remove_file(runtime.directory.join("unexpected")).unwrap();
        for target in ["/etc/passwd", "../outside", "missing", "Python"] {
            let mut manifest: serde_json::Value = serde_json::from_slice(&original).unwrap();
            manifest["entries"]["Python"]["target"] = json!(target);
            fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            fs::remove_file(runtime.directory.join("Python")).unwrap();
            symlink(target, runtime.directory.join("Python")).unwrap();
            assert!(Runtime::inspect(&bundled, &bytes).is_err(), "{target}");
        }
        for marker in [
            format!("pyi-contents-directory openaidr-runtime-{}\0", "A".repeat(64)),
            format!("pyi-contents-directory openaidr-runtime-{}", "a".repeat(64)),
            format!("pyi-contents-directory openaidr-runtime-{}\0pyi-contents-directory openaidr-runtime-{}\0", "a".repeat(64), "b".repeat(64)),
        ] {
            assert!(name(marker.as_bytes()).is_err());
        }
        assert!(name(b"onefile executable").unwrap().is_none());
    }
}

impl Runtime {
    pub(crate) fn inspect(executable: &Path, bytes: &[u8]) -> Result<Option<Self>, String> {
        let Some(name) = name(bytes)? else { return Ok(None); };
        if !fs::symlink_metadata(executable).map_err(|_| invalid())?.is_file() { return Err(invalid()); }
        let parent = executable.parent().ok_or_else(invalid)?;
        real_directory(parent)?;
        let directory = if parent.file_name().is_some_and(|name| name == "MacOS")
            && parent.parent().and_then(Path::file_name).is_some_and(|name| name == "Contents") {
            let contents = parent.parent().ok_or_else(invalid)?;
            real_directory(contents)?;
            real_directory(&contents.join("Resources"))?;
            let frameworks = contents.join("Frameworks");
            if fs::read_link(&frameworks).map_err(|_| invalid())? != Path::new("Resources").join(&name) {
                return Err(invalid());
            }
            contents.join("Resources").join(&name)
        } else {
            parent.join(&name)
        };
        let (manifest, manifest_bytes) = read_manifest(&directory, &name)?;
        validate(&directory, &manifest)?;
        Ok(Some(Self { directory, manifest, manifest_bytes }))
    }

    pub(crate) fn stage(&self, parent: &Path) -> Result<(), String> {
        real_directory(parent)?;
        let destination = parent.join(&self.manifest.name);
        match destination.symlink_metadata() {
            Ok(_) => {
                let (manifest, _) = read_manifest(&destination, &self.manifest.name)?;
                if manifest != self.manifest { return Err(invalid()); }
                return validate(&destination, &manifest);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(invalid()),
        }
        let temporary = tempfile::Builder::new().prefix(".openaidr-runtime-")
            .tempdir_in(parent).map_err(|_| invalid())?;
        for (relative, entry) in &self.manifest.entries {
            let path = temporary.path().join(relative);
            match entry {
                Entry::Directory {} => fs::create_dir(&path).map_err(|_| invalid())?,
                Entry::File { .. } => {
                    fs::copy(self.directory.join(relative), &path).map_err(|_| invalid())?;
                }
                Entry::Symlink { target } => symlink(target, &path).map_err(|_| invalid())?,
            }
        }
        fs::write(temporary.path().join(MANIFEST), &self.manifest_bytes).map_err(|_| invalid())?;
        validate(temporary.path(), &self.manifest)?;
        // Each build owns a directory. Keep older directories for running
        // processes and publish the complete tree before either executable.
        if fs::rename(temporary.path(), &destination).is_err() {
            let (manifest, _) = read_manifest(&destination, &self.manifest.name)?;
            if manifest != self.manifest { return Err(invalid()); }
            validate(&destination, &manifest)?;
        }
        Ok(())
    }
}
