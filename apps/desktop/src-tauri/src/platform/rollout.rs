//! Platform-independent contract shared with scripts/desktop_rollout.py.

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const INVALID: &str =
    "The release rollout policy is invalid or unsupported. The current app was kept.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    schema_version: u64,
    starts_at: String,
    paused: bool,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    after_hours: u64,
    percent: u8,
}

pub(super) struct Policy {
    paused: bool,
    steps: Vec<(i64, u8)>,
}

impl Policy {
    pub(super) fn from_manifest(manifest: &Value) -> Result<Self, &'static str> {
        let raw: RawPolicy =
            serde_json::from_value(manifest["rollout"].clone()).map_err(|_| INVALID)?;
        if raw.schema_version != 1 || raw.steps.is_empty() {
            return Err(INVALID);
        }
        let text = raw.starts_at.as_bytes();
        if !((text.len() == 20 && &text[19..] == b"Z")
            || (text.len() == 25 && &text[19..] == b"+00:00"))
            || !text[..19].iter().enumerate().all(|(i, byte)| match i {
                4 | 7 => *byte == b'-',
                10 => *byte == b'T',
                13 | 16 => *byte == b':',
                _ => byte.is_ascii_digit(),
            })
        {
            return Err(INVALID);
        }
        let start = OffsetDateTime::parse(&raw.starts_at, &Rfc3339).map_err(|_| INVALID)?;
        // Python's publisher accepts years 1..=9999 and rejects leap seconds.
        if start.year() < 1 || &text[17..19] == b"60" {
            return Err(INVALID);
        }
        let mut steps = Vec::with_capacity(raw.steps.len());
        let mut previous = None;
        for step in raw.steps {
            if step.percent > 100
                || previous.map_or(step.after_hours != 0, |(hour, percent)| {
                    step.after_hours <= hour || step.percent < percent
                })
            {
                return Err(INVALID);
            }
            let seconds = step
                .after_hours
                .checked_mul(3600)
                .and_then(|seconds| i64::try_from(seconds).ok())
                .ok_or(INVALID)?;
            let at = start.unix_timestamp().checked_add(seconds).ok_or(INVALID)?;
            if at > 253_402_300_799 {
                // 9999-12-31T23:59:59Z
                return Err(INVALID);
            }
            previous = Some((step.after_hours, step.percent));
            steps.push((at, step.percent));
        }
        if steps.last().map(|step| step.1) != Some(100) {
            return Err(INVALID);
        }
        Ok(Self {
            paused: raw.paused,
            steps,
        })
    }

    fn percent_at(&self, now: i64) -> u8 {
        if self.paused {
            return 0;
        }
        self.steps
            .iter()
            .rev()
            .find(|(at, _)| *at <= now)
            .map_or(0, |(_, percent)| *percent)
    }

    pub(super) fn eligible(&self, version: &str, installation_id: &str, now: i64) -> bool {
        bucket(version, installation_id) < u64::from(self.percent_at(now)) * 100
    }
}

pub(super) fn valid_installation_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bucket(version: &str, installation_id: &str) -> u64 {
    let digest = Sha256::digest(format!("{version}:{installation_id}").as_bytes());
    u64::from_be_bytes(digest[..8].try_into().unwrap()) % 10_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest() -> Value {
        json!({"rollout": {
            "schema_version": 1, "starts_at": "2026-10-16T16:00:00Z", "paused": false,
            "steps": ([1, 5, 10, 25, 50, 75, 100].iter().enumerate().map(|(day, percent)| {
                json!({"after_hours": day * 24, "percent": percent})
            }).collect::<Vec<_>>())
        }})
    }

    #[test]
    fn schedule_boundaries_and_shared_bucket_vector() {
        let mut manifest = manifest();
        let policy = Policy::from_manifest(&manifest).unwrap();
        let start = policy.steps[0].0;
        let version = "2026.10.6+8d5b065";
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(bucket(version, id), 1346);
        assert_eq!(policy.percent_at(start - 1), 0);
        for (day, percent) in [1, 5, 10, 25, 50, 75, 100].into_iter().enumerate() {
            let at = start + day as i64 * 86400;
            assert_eq!(policy.percent_at(at), percent);
            assert_eq!(policy.percent_at(at + 86399), percent);
            assert_eq!(policy.eligible(version, id, at), percent >= 25);
        }
        assert!(!policy.eligible(version, id, start + 3 * 86400 - 1));
        manifest["rollout"]["paused"] = json!(true);
        assert!(!Policy::from_manifest(&manifest)
            .unwrap()
            .eligible(version, id, i64::MAX));
        manifest["rollout"]["paused"] = json!(false);
        assert!(Policy::from_manifest(&manifest)
            .unwrap()
            .eligible(version, id, i64::MAX));
        manifest["rollout"]["starts_at"] = json!("2026-10-16T16:00:00+00:00");
        assert_eq!(
            Policy::from_manifest(&manifest).unwrap().steps,
            policy.steps
        );
        assert_ne!(bucket("2026.10.6+abcdef0", id), bucket(version, id));
        for (id, expected) in [
            ("000000000000000000000000000005c5", 0),
            ("000000000000000000000000000041d2", 99),
            ("000000000000000000000000000022d7", 100),
            ("0000000000000000000000000000238e", 9999),
        ] {
            assert_eq!(bucket(version, id), expected);
            assert!(!policy.eligible(version, id, start - 1));
            assert_eq!(policy.eligible(version, id, start), expected < 100);
            assert!(policy.eligible(version, id, start + 6 * 86400));
        }
        assert!(valid_installation_id(id));
        for invalid in [
            "",
            "0123456789abcdef0123456789abcdeF",
            "0123456789abcdef0123456789abcdef\n",
        ] {
            assert!(!valid_installation_id(invalid));
        }
    }

    #[test]
    fn rejects_invalid_policy_without_defaulting() {
        assert!(Policy::from_manifest(&json!({})).is_err());
        for (field, invalid) in [
            ("schema_version", json!(2)),
            ("schema_version", json!(true)),
            ("schema_version", json!(1.0)),
            ("paused", json!(0)),
            ("unknown", json!(true)),
            ("steps", json!([])),
            ("steps", json!([{"after_hours": 1, "percent": 100}])),
            ("steps", json!([{"after_hours": 0, "percent": 99}])),
            ("steps", json!([{"after_hours": 0, "percent": 101}])),
            ("steps", json!([{"after_hours": 0, "percent": 100.0}])),
            ("steps", json!([{"after_hours": 0.0, "percent": 100}])),
            ("steps", json!([{"after_hours": false, "percent": 100}])),
            ("steps", json!([{"after_hours": -1, "percent": 100}])),
            (
                "steps",
                json!([{"after_hours": 0, "percent": 100, "extra": 1}]),
            ),
            (
                "steps",
                json!([{"after_hours": 0, "percent": 1}, {"after_hours": 0, "percent": 100}]),
            ),
            (
                "steps",
                json!([{"after_hours": 0, "percent": 2}, {"after_hours": 1, "percent": 1}, {"after_hours": 2, "percent": 100}]),
            ),
            (
                "steps",
                json!([{"after_hours": 0, "percent": 0}, {"after_hours": u64::MAX, "percent": 100}]),
            ),
        ] {
            let mut value = manifest();
            value["rollout"][field] = invalid;
            assert!(Policy::from_manifest(&value).is_err(), "accepted {value}");
        }
        for start in [
            "",
            "0000-01-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-10-16t16:00:00Z",
            "2026-10-16T16:00:00z",
            "2026-10-16T16:00:00.0Z",
            "2026-10-16T16:00:00-00:00",
            "2026-10-16T16:00:00+01:00",
            "2026-10-16T16:00:60Z",
            "9999-12-31T23:59:59Z",
        ] {
            let mut value = manifest();
            value["rollout"]["starts_at"] = json!(start);
            assert!(Policy::from_manifest(&value).is_err(), "accepted {start}");
        }
        for field in ["schema_version", "starts_at", "paused", "steps"] {
            let mut value = manifest();
            value["rollout"].as_object_mut().unwrap().remove(field);
            assert!(Policy::from_manifest(&value).is_err());
        }
    }
}
