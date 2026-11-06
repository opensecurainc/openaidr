//! Cancellation boundary shared by native manual update flows.

use std::sync::{Arc, Mutex, atomic::{AtomicU8, Ordering}};

#[derive(Default)]
pub struct ManualUpdate(pub(super) Mutex<Option<Arc<ManualTask>>>);

#[derive(Default)]
pub(super) struct ManualTask {
    // Cancellation and installation compete for a single transition.
    pub(super) phase: AtomicU8,
    cancelled: tokio::sync::Notify,
}

impl ManualTask {
    pub(super) fn cancel(&self) -> Result<(), String> {
        match self.phase.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) | Err(1) => { self.cancelled.notify_one(); Ok(()) }
            _ => Err("Installation has started and cannot be cancelled.".into()),
        }
    }

    pub(super) fn begin_install(&self) -> Result<(), String> {
        self.phase.compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ()).map_err(|_| "The update was cancelled.".into())
    }

    pub(super) async fn run<T>(&self, operation: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
        if self.phase.load(Ordering::SeqCst) == 1 {
            return Err("The update was cancelled.".into());
        }
        tokio::select! {
            biased;
            _ = self.cancelled.notified() => Err("The update was cancelled.".into()),
            result = operation => result,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Intent<'a> { Automatic, Check, Install(&'a str) }
