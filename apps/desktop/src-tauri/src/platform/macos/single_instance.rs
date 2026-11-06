use sha2::{Digest, Sha256};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
        net::UnixListener,
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

pub struct Instance {
    pub socket: UnixListener,
    restarting: AtomicBool,
    _lock: File,
}

pub fn directory(identifier: &str) -> io::Result<PathBuf> {
    let parent = {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        // confstr(3) documents this short per-user cache as exempt from automatic
        // cleanup. Safe-boot cleanup happens before an app can own the lock.
        let length =
            unsafe { libc::confstr(libc::_CS_DARWIN_USER_CACHE_DIR, std::ptr::null_mut(), 0) };
        let mut bytes = vec![0; length];
        let written = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_CACHE_DIR,
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if written == 0 || written > bytes.len() {
            return Err(io::Error::other(
                "Cannot locate the per-user cache directory.",
            ));
        }
        bytes.truncate(written - 1);
        PathBuf::from(OsString::from_vec(bytes))
    };
    // Keep one window across the app ID migration, including older binaries.
    let identifier = if identifier == "com.opensecura.openaidr" {
        "com.opensecura.openaidr.sensor"
    } else { identifier };
    let hash = Sha256::digest(identifier.as_bytes());
    let suffix: String = hash[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    // Keep the socket path below macOS's 104-byte limit in its per-user cache dir.
    Ok(parent.join(format!(".oa-{suffix}")))
}

fn validate_directory(path: &Path, forbidden_permissions: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & forbidden_permissions != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Desktop instance directories must belong to this user and have restricted permissions.",
        ));
    }
    Ok(())
}

impl Instance {
    pub fn begin_restart(&self) {
        self.restarting.store(true, Ordering::SeqCst);
    }

    pub fn is_restarting(&self) -> bool {
        self.restarting.load(Ordering::SeqCst)
    }

    /// Returns None after the existing instance confirms window activation.
    pub fn acquire(directory: &Path) -> io::Result<Option<Self>> {
        // Other accounts must not be able to pre-create or replace this entry.
        let parent = directory.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Missing desktop instance parent directory.",
            )
        })?;
        validate_directory(parent, 0o022)?;
        match DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        validate_directory(directory, 0o077)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("lock"))?;
        let socket_path = directory.join("activate.sock");
        let started = Instant::now();
        loop {
            // Keep this file locked until exit. Never unlink it: another process
            // could still hold the old inode while a new one is created.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                match fs::remove_file(&socket_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                return Ok(Some(Self {
                    socket: UnixListener::bind(socket_path)?,
                    restarting: AtomicBool::new(false),
                    _lock: lock,
                }));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock {
                return Err(error);
            }
            match activate(&socket_path) {
                Ok(()) => return Ok(None),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound
                            | io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
            if started.elapsed() >= Duration::from_secs(5) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "The running desktop app did not confirm window activation.",
                ));
            }
            // The owner may still be binding its socket, or may have exited.
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn activate(path: &Path) -> io::Result<()> {
    // A bounded connect also handles an owner with a full listener backlog.
    let mut stream = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    stream.connect_timeout(&SockAddr::unix(path)?, Duration::from_millis(100))?;
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    stream.set_write_timeout(Some(Duration::from_millis(100)))?;
    stream.write_all(&[1])?;
    let mut reply = [0];
    stream.read_exact(&mut reply)?;
    if reply != [1] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "The running desktop app returned an invalid activation response.",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn app_id_migration_keeps_the_existing_instance_directory() {
    let legacy = directory("com.opensecura.openaidr.sensor").unwrap();
    assert_eq!(directory("com.opensecura.openaidr").unwrap(), legacy);
    assert_ne!(directory("com.example.unrelated").unwrap(), legacy);
}
