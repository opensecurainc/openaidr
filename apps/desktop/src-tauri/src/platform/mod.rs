#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(any(windows, target_os = "linux"))]
pub(crate) mod menu_bar;

pub(crate) mod updater;

#[cfg(target_os = "macos")]
pub(crate) use macos::{sensor_directory, SENSOR_BINARY};
#[cfg(target_os = "windows")]
pub(crate) use windows::bundled_sensor;
#[cfg(target_os = "linux")]
pub(crate) use linux::{sensor_directory, SENSOR_BINARY};

// Release channel compiled into this build (OPENAIDR_RELEASE_CHANNEL, see build.rs).
// `openaidr` is the enterprise channel and the default; `openaidr-oss` is the
// open-source channel. Each channel has its own feed and update verification key.
#[cfg(any(windows, target_os = "linux"))]
pub(crate) const RELEASE_PREFIX: &str = concat!("https://releases.opensecura.ai/", env!("OPENAIDR_RELEASE_CHANNEL"));
pub(crate) const RELEASE_FEED: &str =
    concat!("https://releases.opensecura.ai/", env!("OPENAIDR_RELEASE_CHANNEL"), "/rollout-v2.json");
#[cfg(target_os = "macos")]
pub(crate) const RELEASE_PATH: &str = concat!("/", env!("OPENAIDR_RELEASE_CHANNEL"), "/");
#[cfg(any(windows, target_os = "linux"))]
pub(crate) const UPDATER_PUBLIC_KEY: &str = include_str!(env!("OPENAIDR_UPDATER_PUBLIC_KEY_PATH"));

#[cfg(test)]
mod release_channel_tests {
    #[test]
    fn release_channel_fixes_feed_and_download_prefix() {
        let channel = env!("OPENAIDR_RELEASE_CHANNEL");
        assert!(matches!(channel, "openaidr" | "openaidr-oss"), "unknown channel {channel}");
        assert_eq!(super::RELEASE_FEED, format!("https://releases.opensecura.ai/{channel}/rollout-v2.json"));
        #[cfg(target_os = "macos")]
        assert_eq!(super::RELEASE_PATH, format!("/{channel}/"));
        #[cfg(any(windows, target_os = "linux"))]
        {
            assert_eq!(super::RELEASE_PREFIX, format!("https://releases.opensecura.ai/{channel}"));
            assert!(super::UPDATER_PUBLIC_KEY.contains("minisign public key"));
        }
    }
}
