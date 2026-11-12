//! Bind desktop payloads to their signed source and publication identity.

use base64::{engine::general_purpose::STANDARD, Engine};
use minisign_verify::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[cfg(windows)]
pub(super) const TARGET: &str = "windows-x86_64";
#[cfg(target_os = "linux")]
pub(super) const TARGET: &str = "linux-x86_64";
#[cfg(windows)]
const PLATFORM: &str = "windows";
#[cfg(target_os = "linux")]
const PLATFORM: &str = "linux";
#[cfg(windows)]
const SCHEMA: &str = "openaidr.windows-release.v1";
#[cfg(target_os = "linux")]
const SCHEMA: &str = "openaidr.linux-release.v1";

fn filename(version: &str, commit: &str) -> String {
    #[cfg(windows)]
    return format!("OpenAIDR_{version}_signed-{}_x64-setup.exe", &commit[..7]);
    #[cfg(target_os = "linux")]
    { let _ = commit; format!("OpenAIDR_{version}_amd64.AppImage") }
}
const INVALID: &str = "The signed desktop release metadata is invalid. The current app was kept.";

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Release {
    pub version: String,
    pub build: Value,
    pub filename: String,
    pub sha256: String,
    // Retain the signed bytes for recovery. Never trust editable journal fields
    // in place of the publication that was verified before download.
    pub metadata: String,
    pub metadata_signature: String,
    pub signature: String,
    #[cfg(windows)]
    #[serde(default)]
    pub layout: u64,
}

fn decode(text: &str) -> Result<Vec<u8>, &'static str> {
    if text.len() > 64 * 1024 {
        return Err(INVALID);
    }
    STANDARD.decode(text).map_err(|_| INVALID)
}

pub(super) fn verify_signature(bytes: &[u8], signature: &str, key: &str) -> Result<(), &'static str> {
    let key = decode(key)?;
    let signature = decode(signature)?;
    let key = PublicKey::decode(std::str::from_utf8(&key).map_err(|_| INVALID)?).map_err(|_| INVALID)?;
    let signature = Signature::decode(std::str::from_utf8(&signature).map_err(|_| INVALID)?).map_err(|_| INVALID)?;
    key.verify(bytes, &signature, true).map_err(|_| INVALID)
}

pub(super) fn from_manifest(manifest: &Value, key: &str) -> Result<Release, &'static str> {
    let platform = &manifest["platforms"][TARGET];
    let metadata = platform["metadata"].as_str().ok_or(INVALID)?;
    let metadata_signature = platform["metadata_signature"].as_str().ok_or(INVALID)?;
    let bytes = decode(metadata)?;
    verify_signature(&bytes, metadata_signature, key)?;
    let record: Value = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
    #[cfg(windows)]
    let layout = match record.get("windows_layout") {
        None => 0,
        Some(value) => value.as_u64().filter(|v| *v <= 2).ok_or(INVALID)?,
    };
    #[cfg(target_os = "linux")]
    if record["updater_protocol"].as_u64() != Some(1) { return Err(INVALID); }
    let version = record["version"].as_str().ok_or(INVALID)?;
    let commit = record["commit"].as_str().ok_or(INVALID)?;
    let build = &record["build"];
    if record["schema"] != SCHEMA
        || !version.contains('+')
        || manifest["version"] != version
        || build["source_commit"] != commit
        || crate::build_order(version, build).is_none()
    {
        return Err(INVALID);
    }
    let published = OffsetDateTime::parse(build["published_at"].as_str().ok_or(INVALID)?, &Rfc3339)
        .map_err(|_| INVALID)?;
    let announced = OffsetDateTime::parse(manifest["pub_date"].as_str().ok_or(INVALID)?, &Rfc3339)
        .map_err(|_| INVALID)?;
    if published != announced || published.nanosecond() != 0
        || build["publication_timestamp"].as_i64() != Some(published.unix_timestamp())
    {
        return Err(INVALID);
    }
    let expected_name = filename(version, commit);
    let filename = record["filename"].as_str().ok_or(INVALID)?;
    if filename != expected_name
        || platform["url"] != format!("{}/{version}/{PLATFORM}/{filename}", crate::platform::RELEASE_PREFIX)
    {
        return Err(INVALID);
    }
    let checksum = record["sha256"].as_str().ok_or(INVALID)?;
    if checksum.len() != 64 || !checksum.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(INVALID);
    }
    Ok(Release {
        version: version.into(), build: build.clone(), filename: filename.into(), sha256: checksum.into(),
        metadata: metadata.into(), metadata_signature: metadata_signature.into(),
        signature: platform["signature"].as_str().ok_or(INVALID)?.into(),
        #[cfg(windows)]
        layout,
    })
}

impl Release {
    pub(super) fn url(&self) -> String {
        format!("{}/{}/{PLATFORM}/{}", crate::platform::RELEASE_PREFIX, self.version, self.filename)
    }

    #[cfg(test)]
    pub(super) fn verify_installer(&self, bytes: &[u8], key: &str) -> Result<(), &'static str> {
        verify_signature(bytes, &self.signature, key)?;
        if format!("{:x}", Sha256::digest(bytes)) != self.sha256 {
            return Err("The desktop installer does not match its signed publication. The current app was kept.");
        }
        Ok(())
    }

    pub(super) fn verify_file(&self, file: &mut std::fs::File, key: &str) -> Result<(), String> {
        let checksum = super::super::update_download::verify(file, &self.signature, key, 1024 * 1024 * 1024)?;
        if checksum != self.sha256 {
            return Err("The desktop installer does not match its signed publication. The current app was kept.".into());
        }
        Ok(())
    }

    pub(super) fn revalidate(&self, key: &str) -> Result<Release, &'static str> {
        from_manifest(&serde_json::json!({
            "version": self.version, "pub_date": self.build["published_at"],
            "platforms": {TARGET: {
                "metadata": self.metadata, "metadata_signature": self.metadata_signature,
                "signature": self.signature,
                "url": self.url(),
            }},
        }), key)
    }
}

#[cfg(test)]
pub(super) fn test_fixture() -> Value {
    #[cfg(windows)]
    let mut fixture: Value = serde_json::from_str(include_str!("windows/release-fixture.json")).unwrap();
    #[cfg(target_os = "linux")]
    let mut fixture: Value = serde_json::from_str(include_str!("linux/release-fixture.json")).unwrap();
    for pointer in ["/manifest", "/previous/manifest"] {
        if let Some(manifest) = fixture.pointer_mut(pointer) {
            let url = manifest["platforms"][TARGET]["url"].as_str().unwrap()
                .replacen("https://releases.opensecura.ai/openaidr", crate::platform::RELEASE_PREFIX, 1);
            manifest["platforms"][TARGET]["url"] = Value::String(url);
        }
    }
    fixture
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (Value, String, Vec<u8>) {
        // Signed by an ephemeral test key. Only the public key is retained.
        let fixture = test_fixture();
        (fixture["manifest"].clone(), fixture["key"].as_str().unwrap().into(),
            STANDARD.decode(fixture["installer"].as_str().unwrap()).unwrap())
    }

    #[test]
    fn signed_record_binds_installer_to_publication_before_execution() {
        let (manifest, key, bytes) = fixture();
        let release = from_manifest(&manifest, &key).unwrap();
        release.verify_installer(&bytes, &key).unwrap();
        let mut file = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut file, &bytes).unwrap();
        release.verify_file(&mut file, &key).unwrap();
        let mut changed = release.clone();
        changed.sha256 = "0".repeat(64);
        assert!(changed.verify_file(&mut file, &key).is_err());
        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        std::io::Seek::rewind(&mut file).unwrap();
        std::io::Write::write_all(&mut file, &tampered).unwrap();
        assert!(release.verify_file(&mut file, &key).is_err());
        assert!(release.verify_installer(&tampered, &key).is_err());
        for change in ["version", "pub_date", "url", "metadata", "metadata_signature", "signature"] {
            let mut value = manifest.clone();
            match change {
                "version" => value[change] = json!("2026.10.6+fffffff"),
                "pub_date" => value[change] = json!("2026-10-07T04:00:00+00:00"),
                "url" => value["platforms"][TARGET][change] = json!("https://example.invalid/installer.exe"),
                _ => value["platforms"][TARGET][change] = json!("changed"),
            }
            let result = from_manifest(&value, &key);
            assert!(result.is_err() || result.unwrap().verify_installer(&bytes, &key).is_err(), "accepted {change}");
        }
    }

    #[test]
    fn recovery_uses_signed_fields_instead_of_editable_journal_fields() {
        let (manifest, key, bytes) = fixture();
        let mut release = from_manifest(&manifest, &key).unwrap();
        release.sha256 = "0".repeat(64);
        release.build["publication_timestamp"] = json!(1);
        #[cfg(windows)]
        { release.layout = 2; }
        let recovered = release.revalidate(&key).unwrap();
        #[cfg(windows)]
        assert_eq!(recovered.layout, 0);
        assert_ne!(recovered.sha256, release.sha256);
        assert_ne!(recovered.build, release.build);
        recovered.verify_installer(&bytes, &key).unwrap();
        release.version = "2026.10.6+fffffff".into();
        assert!(release.revalidate(&key).is_err());
    }
}
