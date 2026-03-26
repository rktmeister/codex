use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Barrier;
use tokio::time::sleep;

use crate::function_tool::FunctionCallError;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::handlers::parse_arguments;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;

pub struct TestSyncHandler;

const DEFAULT_TIMEOUT_MS: u64 = 1_000;

static BARRIERS: OnceLock<tokio::sync::Mutex<HashMap<String, BarrierState>>> = OnceLock::new();

struct BarrierState {
    barrier: Arc<Barrier>,
    participants: usize,
}

#[derive(Debug, Deserialize)]
struct BarrierArgs {
    id: String,
    participants: usize,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
struct FileBarrierArgs {
    path: PathBuf,
    participants: usize,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
struct TestSyncArgs {
    #[serde(default)]
    sleep_before_ms: Option<u64>,
    #[serde(default)]
    sleep_after_ms: Option<u64>,
    #[serde(default)]
    barrier: Option<BarrierArgs>,
    #[serde(default)]
    file_barrier: Option<FileBarrierArgs>,
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

fn barrier_map() -> &'static tokio::sync::Mutex<HashMap<String, BarrierState>> {
    BARRIERS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

#[async_trait]
impl ToolHandler for TestSyncHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation { payload, .. } = invocation;

        let arguments = match payload {
            ToolPayload::Function { arguments } => arguments,
            _ => {
                return Err(FunctionCallError::RespondToModel(
                    "test_sync_tool handler received unsupported payload".to_string(),
                ));
            }
        };

        let args: TestSyncArgs = parse_arguments(&arguments)?;

        if let Some(delay) = args.sleep_before_ms
            && delay > 0
        {
            sleep(Duration::from_millis(delay)).await;
        }

        if let Some(barrier) = args.barrier {
            wait_on_barrier(barrier).await?;
        }

        if let Some(file_barrier) = args.file_barrier {
            wait_on_file_barrier(file_barrier).await?;
        }

        if let Some(delay) = args.sleep_after_ms
            && delay > 0
        {
            sleep(Duration::from_millis(delay)).await;
        }

        Ok(FunctionToolOutput::from_text("ok".to_string(), Some(true)))
    }
}

async fn wait_on_barrier(args: BarrierArgs) -> Result<(), FunctionCallError> {
    if args.participants == 0 {
        return Err(FunctionCallError::RespondToModel(
            "barrier participants must be greater than zero".to_string(),
        ));
    }

    if args.timeout_ms == 0 {
        return Err(FunctionCallError::RespondToModel(
            "barrier timeout must be greater than zero".to_string(),
        ));
    }

    let barrier_id = args.id.clone();
    let barrier = {
        let mut map = barrier_map().lock().await;
        match map.entry(barrier_id.clone()) {
            Entry::Occupied(entry) => {
                let state = entry.get();
                if state.participants != args.participants {
                    let existing = state.participants;
                    return Err(FunctionCallError::RespondToModel(format!(
                        "barrier {barrier_id} already registered with {existing} participants"
                    )));
                }
                state.barrier.clone()
            }
            Entry::Vacant(entry) => {
                let barrier = Arc::new(Barrier::new(args.participants));
                entry.insert(BarrierState {
                    barrier: barrier.clone(),
                    participants: args.participants,
                });
                barrier
            }
        }
    };

    let timeout = Duration::from_millis(args.timeout_ms);
    let wait_result = tokio::time::timeout(timeout, barrier.wait())
        .await
        .map_err(|_| {
            FunctionCallError::RespondToModel("test_sync_tool barrier wait timed out".to_string())
        })?;

    if wait_result.is_leader() {
        let mut map = barrier_map().lock().await;
        if let Some(state) = map.get(&barrier_id)
            && Arc::ptr_eq(&state.barrier, &barrier)
        {
            map.remove(&barrier_id);
        }
    }

    Ok(())
}

async fn wait_on_file_barrier(args: FileBarrierArgs) -> Result<(), FunctionCallError> {
    if args.participants == 0 {
        return Err(FunctionCallError::RespondToModel(
            "file barrier participants must be greater than zero".to_string(),
        ));
    }

    if args.timeout_ms == 0 {
        return Err(FunctionCallError::RespondToModel(
            "file barrier timeout must be greater than zero".to_string(),
        ));
    }

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.path)
        .await
        .map_err(|err| {
            FunctionCallError::RespondToModel(format!(
                "failed to open file barrier {}: {err}",
                args.path.display()
            ))
        })?;
    file.write_all(b"ready\n").await.map_err(|err| {
        FunctionCallError::RespondToModel(format!(
            "failed to write file barrier {}: {err}",
            args.path.display()
        ))
    })?;

    let deadline = tokio::time::Instant::now() + Duration::from_millis(args.timeout_ms);
    loop {
        let participants = fs::read_to_string(&args.path).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!(
                "failed to read file barrier {}: {err}",
                args.path.display()
            ))
        })?;
        let count = participants
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();

        if count >= args.participants {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(FunctionCallError::RespondToModel(format!(
                "file barrier {} timed out waiting for {} participants",
                args.path.display(),
                args.participants
            )));
        }

        sleep(Duration::from_millis(10)).await;
    }
}
