//! Disk-backed downloads and bounded verification of signed update artifacts.

use base64::{engine::general_purpose::STANDARD, Engine};
use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use std::{fs::File, io::{Read, Seek, Write}, path::Path, time::Duration};
use tempfile::NamedTempFile;

const FAILED: &str = "The update download or signature verification failed. The current app was kept.";
const TOO_LARGE: &str = "The update exceeds the download size limit. The current app was kept.";

pub(super) fn client(timeout: Duration) -> reqwest::ClientBuilder {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder().https_only(!cfg!(test)).timeout(timeout)
        .connect_timeout(Duration::from_secs(15))
}

pub(super) async fn receive(mut response: reqwest::Response, directory: &Path, limit: u64,
                           mut progress: impl FnMut(u64, Option<u64>)) -> Result<NamedTempFile, String> {
    if !response.status().is_success() { return Err(FAILED.into()); }
    let total = response.content_length();
    if total.is_some_and(|size| size > limit) { return Err(TOO_LARGE.into()); }
    let mut file = NamedTempFile::new_in(directory).map_err(|_| "Cannot stage the update download.")?;
    let mut received = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(|_| FAILED)? {
        received = received.saturating_add(chunk.len() as u64);
        if received > limit { return Err(TOO_LARGE.into()); }
        file.write_all(&chunk).map_err(|_| "Cannot save the update download.")?;
        progress(received, total);
    }
    file.as_file().sync_all().map_err(|_| "Cannot save the update download.")?;
    file.rewind().map_err(|_| FAILED)?;
    Ok(file)
}

pub(super) fn verify(file: &mut File, signature: &str, key: &str, limit: u64) -> Result<String, String> {
    if signature.len() > 64 * 1024 || key.len() > 64 * 1024 { return Err(FAILED.into()); }
    let key = STANDARD.decode(key).map_err(|_| FAILED)?;
    let signature = STANDARD.decode(signature).map_err(|_| FAILED)?;
    let key = PublicKey::decode(std::str::from_utf8(&key).map_err(|_| FAILED)?).map_err(|_| FAILED)?;
    let signature = Signature::decode(std::str::from_utf8(&signature).map_err(|_| FAILED)?).map_err(|_| FAILED)?;
    let mut verifier = key.verify_stream(&signature).map_err(|_| FAILED)?;
    file.rewind().map_err(|_| FAILED)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(|_| FAILED)?;
        if count == 0 { break; }
        size = size.saturating_add(count as u64);
        if size > limit { return Err(TOO_LARGE.into()); }
        verifier.update(&buffer[..count]);
        hash.update(&buffer[..count]);
    }
    verifier.finalize().map_err(|_| FAILED)?;
    file.rewind().map_err(|_| FAILED)?;
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(any(target_os = "macos", windows))]
pub(super) async fn download(update: &tauri_plugin_updater::Update, directory: &Path,
                            key: &str, limit: u64, progress: impl FnMut(u64, Option<u64>))
    -> Result<NamedTempFile, String> {
    let mut builder = client(update.timeout.unwrap_or(Duration::from_secs(15 * 60)));
    if update.no_proxy {
        builder = builder.no_proxy();
    } else if let Some(proxy) = &update.proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy.as_str()).map_err(|_| FAILED)?);
    }
    let mut headers = update.headers.clone();
    headers.entry(reqwest::header::ACCEPT).or_insert(reqwest::header::HeaderValue::from_static("application/octet-stream"));
    let response = builder.build().map_err(|_| FAILED)?.get(update.download_url.clone())
        .headers(headers).send().await.map_err(|_| FAILED)?;
    let mut file = receive(response, directory, limit, progress).await?;
    verify(file.as_file_mut(), &update.signature, key, limit)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, net::TcpListener, thread};

    #[test]
    fn artifact_downloads_stay_on_disk_and_remove_failed_transfers() {
        // Generate the large body a chunk at a time on both sides of a real socket.
        // This test can also run alone under a process memory profiler.
        for case in ["large", "announced", "unannounced", "truncated"] {
            let directory = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let size = if case == "large" { 128 * 1024 * 1024 } else { 8192 };
            let worker = thread::spawn(move || {
                let (mut peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                peer.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
                    let mut byte = [0];
                    if peer.read(&mut byte).unwrap_or(0) == 0 { return; }
                    header.push(byte[0]);
                }
                let length = if case == "unannounced" { String::new() }
                    else { format!("Content-Length: {size}\r\n") };
                write!(peer, "HTTP/1.1 200 OK\r\n{length}Connection: close\r\n\r\n").unwrap();
                if case == "truncated" { return; }
                for _ in 0..size / 8192 {
                    if peer.write_all(&[0; 8192]).is_err() { return; }
                }
            });
            tauri::async_runtime::block_on(async {
                let response = client(Duration::from_secs(30)).no_proxy().build().unwrap()
                    .get(url).send().await.unwrap();
                let limit = if matches!(case, "announced" | "unannounced") { 1024 } else { size };
                let mut written = 0;
                let mut checked = 0;
                let result = receive(response, directory.path(), limit, |received, _| {
                    if checked == 0 || received - checked >= 8 * 1024 * 1024 || received == size {
                        let entry = fs::read_dir(directory.path()).unwrap().next().unwrap().unwrap();
                        // Windows directory metadata can lag writes to an open file.
                        // Read the latest byte through a handle while download is active.
                        let mut saved = File::open(entry.path()).unwrap();
                        saved.seek(std::io::SeekFrom::Start(received - 1)).unwrap();
                        let mut byte = [1];
                        saved.read_exact(&mut byte).unwrap();
                        assert_eq!(byte, [0]);
                        checked = received;
                    }
                    written = received;
                }).await;
                if case == "large" {
                    let mut file = result.unwrap();
                    assert_eq!(written, size);
                    let fixture: serde_json::Value = serde_json::from_str(include_str!("linux/release-fixture.json")).unwrap();
                    let signature = fixture["manifest"]["platforms"]["linux-x86_64"]["signature"].as_str().unwrap();
                    let key = fixture["key"].as_str().unwrap();
                    assert!(verify(file.as_file_mut(), signature, key, size).is_err());
                    assert_eq!(file.stream_position().unwrap(), size);
                    assert!(verify(file.as_file_mut(), signature, key, 1024).unwrap_err().contains("size limit"));
                } else {
                    assert!(result.is_err(), "{case}");
                }
                assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
            });
            worker.join().unwrap();
        }
    }
}
