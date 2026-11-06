//! Persist release-server outages without warning about brief connection failures.

use serde::{Deserialize, Serialize};

pub(super) const UNREACHABLE: &str = "Cannot check the release server. The current app was kept.";
const WARNING_DELAY: u64 = 24 * 60 * 60;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct CheckHealth {
    unreachable_since: Option<u64>,
}

impl CheckHealth {
    #[cfg(any(target_os = "macos", windows))]
    pub(super) async fn check(&mut self, updater: &tauri_plugin_updater::Updater, now: u64)
        -> Result<Option<tauri_plugin_updater::Update>, String> {
        let result = updater.check().await.map_err(release_error);
        self.record(&result, now);
        result
    }

    pub(super) fn record<T>(&mut self, result: &Result<T, String>, now: u64) {
        if result.as_ref().err().is_some_and(|error| error == UNREACHABLE) {
            // A clock correction must not leave the start of an outage in the future.
            self.unreachable_since = Some(self.unreachable_since.map_or(now, |since| since.min(now)));
        } else {
            self.unreachable_since = None;
        }
    }

    pub(super) fn warning_deferred(&self, error: Option<&str>, now: u64) -> bool {
        error == Some(UNREACHABLE)
            && self.unreachable_since.is_none_or(|since| now.saturating_sub(since) <= WARNING_DELAY)
    }
}

#[cfg(any(target_os = "macos", windows))]
fn release_error(error: tauri_plugin_updater::Error) -> String {
    use tauri_plugin_updater::Error;
    let unavailable = match error {
        Error::Reqwest(error) => error.is_connect() || error.is_timeout() || error.is_body() || error.is_request(),
        // Tauri uses this error when the feed returns a non-success HTTP status.
        Error::ReleaseNotFound => true,
        _ => false,
    };
    if unavailable { UNREACHABLE } else { "Cannot read the release information. The current app was kept." }.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_warning_waits_more_than_a_day_across_restarts_and_resets_after_recovery() {
        let mut health: CheckHealth = serde_json::from_str("{}").unwrap();
        let failure: Result<(), String> = Err(UNREACHABLE.into());
        let start = 100_000;
        // Older journals have no outage history, so they cannot establish a 24-hour outage.
        assert!(health.warning_deferred(Some(UNREACHABLE), start));
        health.record(&failure, start);
        for elapsed in [0, 3 * 60 * 60, WARNING_DELAY - 1, WARNING_DELAY, WARNING_DELAY + 1] {
            health = serde_json::from_slice(&serde_json::to_vec(&health).unwrap()).unwrap();
            health.record(&failure, start + elapsed);
            assert_eq!(health.warning_deferred(Some(UNREACHABLE), start + elapsed), elapsed <= WARNING_DELAY);
        }
        health.record(&Ok(()), start + WARNING_DELAY + 2);
        assert!(!health.warning_deferred(None, start + WARNING_DELAY + 2));
        health.record(&failure, start + WARNING_DELAY + 3);
        assert!(health.warning_deferred(Some(UNREACHABLE), start + WARNING_DELAY + 3));
    }

    #[test]
    fn other_update_errors_are_immediate_and_clock_corrections_do_not_extend_the_outage() {
        let mut health = CheckHealth::default();
        let failure: Result<(), String> = Err(UNREACHABLE.into());
        health.record(&failure, 100_000);
        assert!(!health.warning_deferred(Some("The update signature is invalid."), 100_001));
        assert!(!health.warning_deferred(None, 100_001));
        health.record(&failure, 50_000);
        assert!(health.warning_deferred(Some(UNREACHABLE), 50_000 + WARNING_DELAY));
        assert!(!health.warning_deferred(Some(UNREACHABLE), 50_001 + WARNING_DELAY));
        health.record::<()>(&Err("The release manifest is invalid.".into()), 150_000);
        health.record(&failure, 150_001);
        assert!(health.warning_deferred(Some(UNREACHABLE), 150_001));
    }
}
