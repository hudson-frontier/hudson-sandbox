//! Bounded independent reconciliation loops sharing one notification listener.
use crate::{Controller, ControllerError, Tick, wakeup};
use tokio::task::{JoinError, JoinSet};

pub const DEFAULT_WORKERS: u32 = 4;
pub const MAX_WORKERS: u32 = 16;

/// Each worker owns its scheduling cursor and at most one cached upload source.
/// Database claims, rather than this process, arbitrate operation ownership.
/// Dropping the pool aborts workers and its single notification listener.
#[derive(Debug)]
pub struct WorkerPool {
    tasks: JoinSet<()>,
    _wakeup: wakeup::WorkWakeup,
}

impl WorkerPool {
    pub fn start(controller: &Controller, count: u32) -> Result<Self, ControllerError> {
        if !(1..=MAX_WORKERS).contains(&count) {
            return Err(ControllerError::InvalidWorkerCount);
        }
        let listener = wakeup::WorkWakeup::start(controller.store.clone());
        let mut tasks = JoinSet::new();
        for index in 0..count {
            let mut worker = Controller {
                new_work_compatible: controller.new_work_compatible,
                launch_permits_required: controller.launch_permits_required,
                store: controller.store.clone(),
                config: controller.config.clone(),
                client: controller.client.clone(),
                archive_client: controller.archive_client.clone(),
                operation_cursor: index as usize,
                authority_sync: controller.authority_sync.clone(),
                file_sources: controller.file_sources.clone(),
                file_cache: None,
            };
            let mut signal = listener.subscribe();
            tasks.spawn(async move {
                loop {
                    match worker.tick().await {
                        Ok(Tick::Idle) => {}
                        Ok(tick) => eprintln!("sandbox controller worker {index}: {tick:?}"),
                        Err(error) => eprintln!("sandbox controller worker {index}: {error}"),
                    }
                    wakeup::wait(&mut signal).await;
                }
            });
        }
        Ok(Self {
            tasks,
            _wakeup: listener,
        })
    }

    /// A loop exiting or panicking must be reported to the process supervisor.
    pub async fn join_next(&mut self) -> Option<Result<(), JoinError>> {
        self.tasks.join_next().await
    }

    /// Cancel in-flight work and wait for its futures to be dropped. Persisted
    /// claims expire normally; cancellation cannot authorize another dispatch.
    pub async fn shutdown(&mut self) {
        self.tasks.shutdown().await;
    }
}
