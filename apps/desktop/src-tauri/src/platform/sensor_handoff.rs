//! Complete desktop sensor setup while preserving unmanaged services.

use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub(super) fn finish(expected: &str, timeout: Duration,
    mut bridge: impl FnMut(Value) -> Result<Value, String>) -> Result<(), String> {
    let status = |bridge: &mut dyn FnMut(Value) -> Result<Value, String>| bridge(json!({"action":"status"}))
        .map_err(|_| "The app was updated, but sensor status could not be read. Reopen OpenAIDR to retry.".to_string());
    let before = status(&mut bridge)?;
    let enrolled = before["enrolled"].as_bool().ok_or("The updated sensor returned an invalid status.")?;
    if !enrolled || before["foreground"] == true {
        if before["running"] == true && before["service_version"].as_str() != Some(expected) {
            return Err(format!("The running sensor does not match OpenAIDR {expected}. Stop the manually started sensor or enable managed setup, then retry."));
        }
        return Ok(());
    }
    let result = bridge(json!({"action":"desktop.update.setup"}))
        .map_err(|_| "The app was updated, but sensor setup needs a retry. Reopen OpenAIDR to retry.")?;
    if !result["steps"].as_array().is_some_and(|steps| steps.iter().all(|step| step["ok"] == true)) {
        return Err("The app was updated, but sensor setup needs a retry. Reopen OpenAIDR to retry.".into());
    }
    let deadline = Instant::now() + timeout;
    loop {
        let current = status(&mut bridge)?;
        if current["running"] == true && current["service_version"].as_str() == Some(expected) { break; }
        if Instant::now() >= deadline { return Err("The app was updated, but its background sensor did not become healthy. Reopen OpenAIDR to retry.".into()); }
        std::thread::sleep(Duration::from_secs(2));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensor_handoff_checks_health_and_preserves_unmanaged_services() {
        for status in [json!({"enrolled":false}), json!({"enrolled":true,"foreground":true})] {
            let mut calls = Vec::new();
            finish("2026.10.6+1a1a1a1", Duration::ZERO, |payload| {
                calls.push(payload);
                Ok(status.clone())
            }).unwrap();
            assert_eq!(calls, [json!({"action":"status"})]);
        }
        for flag in ["foreground", "enrolled"] {
            let mut state = json!({"enrolled":true,"running":true,"service_version":"2026.10.6+0000000"});
            state[flag] = json!(flag != "enrolled");
            assert!(finish("2026.10.6+1a1a1a1", Duration::ZERO, |_| Ok(state.clone())).is_err());
            state["service_version"] = json!("2026.10.6+1a1a1a1");
            finish("2026.10.6+1a1a1a1", Duration::ZERO, |_| Ok(state.clone())).unwrap();
        }
        for case in ["healthy", "newer", "stopped", "wrong_version", "failed_setup", "private_error", "invalid_status",
            "no_actions", "no_actions_unhealthy", "invalid_setup", "downgrade", "foreground_mismatch", "disabled", "disabled_mismatch"] {
            let mut calls = Vec::new();
            let result = finish("2026.10.6+1a1a1a1", Duration::ZERO, |payload| {
                calls.push(payload);
                Ok(match calls.len() {
                    1 if case == "invalid_status" => json!({}),
                    1 => json!({"enrolled":true,"disabled":case.starts_with("disabled"),"service_newer":case == "newer","service_downgrade":case == "downgrade"}),
                    2 if case == "private_error" => return Err("private-sensor-details".into()),
                    2 if case == "invalid_setup" => json!({}),
                    2 if case.starts_with("no_actions") => json!({"steps":[]}),
                    2 => json!({"steps":[{"ok":case != "failed_setup"}]}),
                    _ => json!({"enrolled":true,"running":case != "stopped" && case != "no_actions_unhealthy", "service_newer":case == "newer",
                        "foreground":case == "foreground_mismatch", "disabled":case.starts_with("disabled"),
                        "service_version":if ["wrong_version", "newer", "foreground_mismatch", "disabled_mismatch"].contains(&case) { "2026.10.6+0000000" } else { "2026.10.6+1a1a1a1" }}),
                })
            });
            assert_eq!(result.is_ok(), ["healthy", "downgrade", "no_actions", "disabled"].contains(&case), "{case}");
            if case.starts_with("no_actions") { assert_eq!(calls.len(), 3); }
            if let Err(error) = result { assert!(!error.contains("private-sensor-details")); }
            if case != "invalid_status" { assert_eq!(calls[1], json!({"action":"desktop.update.setup"})); }
        }
    }

}
