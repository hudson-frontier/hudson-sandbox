//! One-host controller. Operator provisioning and TLS are required in every mode.
use clap::Parser;
use sandbox_controller::{
    Controller, ControllerConfig,
    workers::{DEFAULT_WORKERS, MAX_WORKERS, WorkerPool},
};
use sandbox_protocol::HostId;
use sandbox_store::Store;
use std::{collections::BTreeSet, path::PathBuf, time::Duration};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    host_id: HostId,
    #[arg(long)]
    host_epoch: i64,
    #[arg(long)]
    ca_cert: PathBuf,
    #[arg(long)]
    client_cert: PathBuf,
    #[arg(long)]
    client_key: PathBuf,
    #[arg(long, required = true)]
    image_digest: Vec<String>,
    /// Development only. Persist and expose simulated evidence; never run against production data.
    #[arg(long, default_value_t = false)]
    allow_simulated: bool,
    /// Run one maintenance/operation tick and exit; useful for controlled diagnostics.
    #[arg(long)]
    once: bool,
    /// Independent reconciliation loops; --once always runs a single tick.
    #[arg(long, default_value_t = DEFAULT_WORKERS, value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_WORKERS)))]
    workers: u32,
    /// Run an independent output publisher; supervisor needs --output-config.
    #[arg(long)]
    archive_output: bool,
    /// Reclaim acknowledged history after external consumers retire.
    #[arg(long)]
    retire_history: bool,
    /// Reclaim released physical allocation records after history retirement.
    #[arg(long, requires = "retire_history", conflicts_with = "allow_simulated")]
    retire_allocations: bool,
    /// Private read-only source store for file writes.
    #[arg(long)]
    file_source_config: Option<std::path::PathBuf>,
    #[arg(long, default_value_t = 86400)]
    output_retention_seconds: u32,
    #[arg(long, default_value_t = 3600)]
    output_cleanup_grace_seconds: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // One shared listener plus room for concurrent transactions and publishers.
    let store = Store::connect(&args.database_url, 8 + 2 * args.workers).await?;
    store.migrate().await?;
    let mut controller = Controller::connect(
        store.clone(),
        ControllerConfig {
            endpoint: args.endpoint,
            host: args.host_id,
            epoch: args.host_epoch,
            allowed_images: BTreeSet::from_iter(args.image_digest),
            allow_simulated: args.allow_simulated,
        },
        &std::fs::read(args.ca_cert)?,
        &std::fs::read(args.client_cert)?,
        &std::fs::read(args.client_key)?,
    )
    .await?;
    if let Some(path) = args.file_source_config {
        controller = controller.with_file_sources(std::sync::Arc::new(
            sandbox_artifacts::S3Config::read_private(&path)?.build_sources()?,
        ));
    }
    if args.once {
        eprintln!("{:?}", controller.tick().await?);
        if args.archive_output {
            eprintln!(
                "{:?}",
                controller
                    .output_archiver(
                        args.output_retention_seconds,
                        args.output_cleanup_grace_seconds
                    )?
                    .tick()
                    .await?
            );
        }
        if args.retire_history {
            let mut worker = controller.history_retirer();
            // Both domains and both lifecycle proof paths receive a turn.
            for _ in 0..4 {
                eprintln!("{:?}", worker.tick().await?);
            }
        }
        if args.retire_allocations {
            eprintln!("{:?}", controller.allocation_retirer().tick().await?);
        }
        return Ok(());
    }
    let mut workers = WorkerPool::start(&controller, args.workers)?;
    let allocations = if args.retire_allocations {
        let mut worker = controller.allocation_retirer();
        Some(tokio::spawn(async move {
            loop {
                match worker.tick().await {
                    Ok(sandbox_controller::retirement::RetirementTick::Idle)
                    | Ok(sandbox_controller::retirement::RetirementTick::Deferred) => {}
                    Ok(tick) => eprintln!("sandbox allocation retirement: {tick:?}"),
                    Err(error) => eprintln!("sandbox allocation retirement: {error}"),
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }))
    } else {
        None
    };
    let retirement = if args.retire_history {
        let mut worker = controller.history_retirer();
        Some(tokio::spawn(async move {
            loop {
                match worker.tick().await {
                    Ok(sandbox_controller::history::HistoryTick::Idle) => {}
                    Ok(tick) => eprintln!("sandbox history: {tick:?}"),
                    Err(error) => eprintln!("sandbox history: {error}"),
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }))
    } else {
        None
    };
    let archival = if args.archive_output {
        let mut worker = controller.output_archiver(
            args.output_retention_seconds,
            args.output_cleanup_grace_seconds,
        )?;
        Some(tokio::spawn(async move {
            loop {
                match worker.tick().await {
                    Ok(sandbox_controller::archive::ArchiveTick::Idle) => {}
                    Ok(tick) => eprintln!("sandbox output: {tick:?}"),
                    Err(error) => eprintln!("sandbox output: {error}"),
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }))
    } else {
        None
    };
    let stopped = tokio::select! {
        signal = tokio::signal::ctrl_c() => signal.map_err(anyhow::Error::from),
        result = workers.join_next() => Err(anyhow::anyhow!("controller worker exited: {result:?}")),
    };
    workers.shutdown().await;
    if let Some(task) = retirement {
        task.abort();
    }
    if let Some(task) = allocations {
        task.abort();
    }
    if let Some(task) = archival {
        task.abort();
    }
    stopped
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn worker_count_is_bounded_and_single_tick_mode_remains_available() {
        let command = Args::command();
        let host = HostId::generate().to_string();
        let args = [
            "--database-url",
            "postgres://unused",
            "--endpoint",
            "https://unused",
            "--host-id",
            &host,
            "--host-epoch",
            "1",
            "--ca-cert",
            "ca",
            "--client-cert",
            "cert",
            "--client-key",
            "key",
            "--image-digest",
            "sha256:unused",
        ];
        // Clap validates the worker count independently of runtime connection.
        for count in ["0", "17", "-1"] {
            let result = command.clone().try_get_matches_from(
                ["sandbox-controller"]
                    .into_iter()
                    .chain(args)
                    .chain(["--workers", count]),
            );
            assert!(result.is_err());
        }
        for count in ["1", "4", "16"] {
            let result = command.clone().try_get_matches_from(
                ["sandbox-controller"].into_iter().chain(args).chain([
                    "--workers",
                    count,
                    "--once",
                ]),
            );
            assert!(result.is_ok(), "{result:?}");
        }
    }
}
