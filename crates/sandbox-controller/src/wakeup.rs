//! Bounded notification-assisted polling. Notifications never carry execution authority.
use std::time::Duration;

use sandbox_store::{Store, work::WORK_CHANNEL};
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{Instant, sleep, sleep_until, timeout},
};

const POLL: Duration = Duration::from_millis(500);
const MIN_WAIT: Duration = Duration::from_millis(50);
const RECONNECT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeReason {
    Notification,
    Poll,
}

/// One background listener with a coalesced signal, not an in-memory work queue.
/// Dropping it aborts the listener; the database pool remains owned by the caller.
#[derive(Debug)]
pub struct WorkWakeup {
    signal: watch::Receiver<()>,
    task: JoinHandle<()>,
}

impl Drop for WorkWakeup {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl WorkWakeup {
    pub fn start(store: Store) -> Self {
        let (sender, signal) = watch::channel(());
        let task = tokio::spawn(async move {
            while !sender.is_closed() && !store.pool().is_closed() {
                if let Ok(Ok(mut listener)) = timeout(RECONNECT, store.listen_for_work()).await {
                    // Covers work committed before LISTEN and during a disconnect.
                    let _ = sender.send(());
                    while let Ok(Some(notification)) = listener.try_recv().await {
                        if notification.channel() == WORK_CHANNEL
                            && notification.payload().is_empty()
                        {
                            if sender.send(()).is_err() {
                                return;
                            }
                            tokio::task::yield_now().await;
                        }
                    }
                }
                // A missing, overloaded or disconnected listener cannot stall
                // the controller's independent periodic scan or spin reconnects.
                sleep(RECONNECT).await;
            }
        });
        Self { signal, task }
    }

    pub async fn wait(&mut self) -> WakeReason {
        wait(&mut self.signal).await
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<()> {
        self.signal.clone()
    }
}

pub(crate) async fn wait(signal: &mut watch::Receiver<()>) -> WakeReason {
    let start = Instant::now();
    tokio::select! {
        _ = sleep_until(start + POLL) => WakeReason::Poll,
        changed = signal.changed() => {
            if changed.is_err() {
                sleep_until(start + POLL).await;
                WakeReason::Poll
            } else {
                // Coalesce bursts and cap wake-driven scans at twenty per
                // second, without extending the original polling deadline.
                sleep_until(start + MIN_WAIT).await;
                WakeReason::Notification
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn notification_bursts_are_coalesced_and_cannot_spin_the_loop() {
        let (sender, mut receiver) = watch::channel(());
        let start = Instant::now();
        let task = tokio::spawn(async move { wait(&mut receiver).await });
        tokio::task::yield_now().await;
        for _ in 0..100 {
            sender.send(()).unwrap();
        }
        tokio::time::advance(MIN_WAIT - Duration::from_millis(1)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(task.await.unwrap(), WakeReason::Notification);
        assert_eq!(start.elapsed(), MIN_WAIT);
    }

    #[tokio::test(start_paused = true)]
    async fn absent_or_closed_listener_keeps_the_periodic_poll_deadline() {
        for closed in [false, true] {
            let (sender, mut receiver) = watch::channel(());
            let start = Instant::now();
            let task = tokio::spawn(async move { wait(&mut receiver).await });
            tokio::task::yield_now().await;
            if closed {
                drop(sender);
            }
            tokio::time::advance(POLL - Duration::from_millis(1)).await;
            assert!(!task.is_finished());
            tokio::time::advance(Duration::from_millis(1)).await;
            assert_eq!(task.await.unwrap(), WakeReason::Poll);
            assert_eq!(start.elapsed(), POLL);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn late_notification_does_not_add_another_wait_to_the_poll_deadline() {
        let (sender, mut receiver) = watch::channel(());
        let start = Instant::now();
        let task = tokio::spawn(async move { wait(&mut receiver).await });
        tokio::task::yield_now().await;
        tokio::time::advance(POLL - Duration::from_millis(1)).await;
        sender.send(()).unwrap();
        assert_eq!(task.await.unwrap(), WakeReason::Notification);
        assert!(start.elapsed() < POLL);
    }
}
