//! Installed Windows hooks contact the running sensor without an interpreter.
#![cfg_attr(not(windows), allow(dead_code))]
use serde_json::Value;
use std::{io::Read, net::SocketAddr, path::Path};
use yaml_rust2::YamlLoader;

const MAX_BYTES: u64 = 4 << 20;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn bounded(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("oversized hook data".into());
    }
    Ok(bytes)
}

fn unhex(value: &str) -> Result<Vec<u8>> {
    if value.len() > 64 * 1024 || !value.len().is_multiple_of(2) {
        return Err("invalid argument".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| "invalid hook descriptor".into())
}

fn endpoint(path: &Path) -> Result<(SocketAddr, String)> {
    let bytes = bounded(std::fs::File::open(path)?)?;
    let documents = YamlLoader::load_from_str(std::str::from_utf8(&bytes)?)?;
    if documents.len() != 1 {
        return Err("invalid sensor config".into());
    }
    let config = &documents[0];
    if config.as_hash().is_none() {
        return Err("invalid sensor config".into());
    }
    let address: SocketAddr = config["listen"]
        .as_str()
        .ok_or("missing loopback listener")?
        .parse()?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("loopback required".into());
    }
    let token = config["telemetry"]["local_token"].as_str().unwrap_or("");
    if token.bytes().any(|b| !(32..127).contains(&b)) {
        return Err("invalid local token".into());
    }
    Ok((address, token.to_owned()))
}

fn output(bytes: &[u8]) -> Result<Vec<u8>> {
    let reply: Value = serde_json::from_slice(bytes)?;
    if !reply.is_object()
        || reply
            .get("failed")
            .is_some_and(|v| v != &Value::Bool(false))
    {
        return Err("unavailable hook response".into());
    }
    let value = reply
        .get("output")
        .or_else(|| reply.get("claude_code"))
        .ok_or("missing output")?;
    let object = value.as_object().ok_or("invalid output")?;
    if object.is_empty() {
        return Ok(Vec::new());
    }
    // Windows PowerShell can decode child output with a legacy code page.
    // JSON Unicode escapes preserve the exact text through every shell.
    let mut ascii = String::new();
    for character in serde_json::to_string(value)?.chars() {
        if character.is_ascii() {
            ascii.push(character);
        } else {
            for unit in character.encode_utf16(&mut [0; 2]) {
                ascii.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    Ok(ascii.into_bytes())
}

fn query(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[cfg(windows)]
mod windows;

fn main() {
    // An ordinary hook error must never print diagnostics or deny the action.
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<String> = std::env::args().collect();
    if args
        .get(1)
        .is_some_and(|s| s == "build-info" || s == "version")
    {
        if let Some(info) = option_env!("OPENAIDR_HOOK_BUILD_INFO") {
            if args[1] == "build-info" {
                println!("{info}");
            } else if let Ok(value) = serde_json::from_str::<Value>(info) {
                if let Some(version) = value["version"].as_str() {
                    println!("openaidr {version}");
                }
            }
        }
        return;
    }
    #[cfg(windows)]
    let _ = windows::main(&args);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unavailable_or_malformed_output_and_preserves_restrictions() {
        for bytes in [
            b"null".as_slice(),
            b"{}",
            b"{\"failed\":true,\"output\":{}}",
            b"{\"output\":[]}",
        ] {
            assert!(output(bytes).is_err());
        }
        assert_eq!(output(br#"{"output":{}}"#).unwrap(), b"");
        let deny = br#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#;
        let reply = format!("{{\"output\":{}}}", std::str::from_utf8(deny).unwrap());
        assert_eq!(output(reply.as_bytes()).unwrap(), deny);
        let unicode = serde_json::json!({"output": {"reason": "café 中文 🦀"}});
        let encoded = output(&serde_json::to_vec(&unicode).unwrap()).unwrap();
        assert!(encoded.is_ascii());
        assert_eq!(
            serde_json::from_slice::<Value>(&encoded).unwrap(),
            unicode["output"]
        );
        assert_eq!(
            unhex(&hex("café 中文".as_bytes())).unwrap(),
            "café 中文".as_bytes()
        );
        assert!(unhex("a").is_err());
        assert!(unhex("xx").is_err());
    }
}
