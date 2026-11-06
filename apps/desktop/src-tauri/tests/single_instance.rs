#![cfg(target_os = "macos")]

#[path = "../src/platform/macos/single_instance.rs"]
mod single_instance;

use single_instance::{directory, Instance};
use std::{
    fs::{self, DirBuilder},
    io::{self, BufRead, Read, Write},
    os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
        let path = directory(&format!(
            "openaidr.instance.test.{}.{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
        .unwrap();
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(directory: &Path, events: mpsc::Sender<(u32, String)>, behavior: &str) -> Process {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "instance_child", "--nocapture"])
        .env("OPENAIDR_INSTANCE_TEST_DIRECTORY", directory)
        .env("OPENAIDR_INSTANCE_TEST_BEHAVIOR", behavior)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let stdout = child.stdout.take().unwrap();
    thread::spawn(move || {
        for line in io::BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some((_, event)) = line.split_once("INSTANCE_EVENT=") {
                let _ = events.send((pid, event.to_owned()));
            }
        }
    });
    Process(child)
}

fn command(child: &mut Process) {
    child.0.stdin.as_mut().unwrap().write_all(b"x").unwrap();
}

fn event(events: &mpsc::Receiver<(u32, String)>) -> (u32, String) {
    events.recv_timeout(Duration::from_secs(10)).unwrap()
}

#[test]
fn simultaneous_processes_activate_one_owner_and_recover_after_exit() {
    let scratch = Scratch::new();
    let (send, receive) = mpsc::channel();
    let mut children: Vec<_> = (0..4)
        .map(|_| spawn(&scratch.0, send.clone(), "activate"))
        .collect();
    for child in &mut children {
        command(child);
    }
    let mut owners = Vec::new();
    let mut secondary = 0;
    let mut activations = 0;
    while owners.len() + secondary < children.len() || activations < children.len() - 1 {
        let (pid, state) = event(&receive);
        match state.as_str() {
            "primary" => owners.push(pid),
            "secondary" => secondary += 1,
            "activated" => activations += 1,
            _ => panic!("Unexpected child event: {state}"),
        }
    }
    assert_eq!(owners.len(), 1);
    assert_eq!(secondary, 3);
    for child in &mut children {
        if child.0.id() == owners[0] {
            child.0.kill().unwrap();
            child.0.wait().unwrap();
        } else {
            assert!(child.0.wait().unwrap().success());
        }
    }
    // A forced exit leaves the socket behind but releases the kernel lock.
    // The next owner removes that socket. Normal exit must also permit reopening.
    for _ in 0..2 {
        let mut child = spawn(&scratch.0, send.clone(), "activate");
        command(&mut child);
        assert_eq!(event(&receive), (child.0.id(), "primary".into()));
        command(&mut child);
        assert!(child.0.wait().unwrap().success());
    }
}

#[test]
fn relaunch_takes_ownership_during_exit_and_updater_restart() {
    for behavior in ["exit", "restart"] {
        let scratch = Scratch::new();
        let (send, receive) = mpsc::channel();
        let mut owner = spawn(&scratch.0, send.clone(), behavior);
        command(&mut owner);
        assert_eq!(event(&receive), (owner.0.id(), "primary".into()));
        let mut successor = spawn(&scratch.0, send, "activate");
        command(&mut successor);
        let mut events = [event(&receive), event(&receive)];
        events.sort_by_key(|event| event.0);
        let mut expected = [
            (owner.0.id(), "shutdown".into()),
            (successor.0.id(), "primary".into()),
        ];
        expected.sort_by_key(|event| event.0);
        assert_eq!(events, expected);
        assert!(owner.0.wait().unwrap().success());
        command(&mut successor);
        assert!(successor.0.wait().unwrap().success());
    }
}

#[test]
fn rejects_shared_directories_and_symlinks() {
    let scratch = Scratch::new();
    let cache = Command::new("/usr/bin/getconf")
        .arg("DARWIN_USER_CACHE_DIR")
        .output()
        .unwrap();
    assert!(cache.status.success());
    let cache = String::from_utf8(cache.stdout).unwrap();
    assert_eq!(scratch.0.parent().unwrap(), Path::new(cache.trim()));
    let claimed = scratch.0.join("x");
    DirBuilder::new().mode(0o700).create(&claimed).unwrap();
    fs::write(claimed.join("lock"), b"keep this file").unwrap();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        Instance::acquire(&claimed).err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(fs::read(claimed.join("lock")).unwrap(), b"keep this file");
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Instance::acquire(&claimed).unwrap().is_some());
    assert_eq!(
        Instance::acquire(&scratch.0).err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    let linked = scratch.0.join("linked");
    symlink(&scratch.0, &linked).unwrap();
    assert_eq!(
        Instance::acquire(&linked).err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    let target = scratch.0.join("unchanged");
    fs::write(&target, b"keep this file").unwrap();
    symlink(&target, scratch.0.join("lock")).unwrap();
    assert!(Instance::acquire(&scratch.0).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"keep this file");
}

// The test binary also supplies real competing processes for the test above.
#[test]
fn instance_child() {
    let Some(path) = std::env::var_os("OPENAIDR_INSTANCE_TEST_DIRECTORY") else {
        return;
    };
    let mut input = io::stdin().lock();
    input.read_exact(&mut [0]).unwrap();
    if let Some(instance) = Instance::acquire(Path::new(&path)).unwrap() {
        let instance = Arc::new(instance);
        let behavior = std::env::var("OPENAIDR_INSTANCE_TEST_BEHAVIOR").unwrap();
        if behavior == "restart" {
            instance.begin_restart();
        }
        println!("INSTANCE_EVENT=primary");
        io::stdout().flush().unwrap();
        let socket = instance.socket.try_clone().unwrap();
        let owner = instance.clone();
        thread::spawn(move || loop {
            let (mut stream, _) = socket.accept().unwrap();
            let mut message = [0];
            stream.read_exact(&mut message).unwrap();
            assert_eq!(message, [1]);
            if behavior == "exit" || owner.is_restarting() {
                println!("INSTANCE_EVENT=shutdown");
                io::stdout().flush().unwrap();
                std::process::exit(0);
            }
            stream.write_all(&[1]).unwrap();
            println!("INSTANCE_EVENT=activated");
            io::stdout().flush().unwrap();
            if behavior == "restart" {
                std::process::exit(0);
            }
        });
        // Child::wait closes stdin, including during forced-exit cleanup.
        let _ = input.read_exact(&mut [0]);
    } else {
        println!("INSTANCE_EVENT=secondary");
        io::stdout().flush().unwrap();
    }
}
