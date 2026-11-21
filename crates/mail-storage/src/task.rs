//! The task store: durable ownership, progress and results of MCP tasks.
//!
//! ADR-0010 lists "task ownership/state/result reference/cancellation" as
//! durable state, and section 6 adds the rule that matters: a task and its
//! result handle are persisted **before** the MCP call returns
//! `resultType: task`. A task that is announced and then lost is a task
//! that no client can ever wait for.
//!
//! The store is fenced like the mailbox lease: a claim carries a fencing
//! token, and a worker whose token is stale cannot report progress or a
//! result. Two workers therefore cannot both own one task, and a worker
//! that was paused cannot come back and overwrite the result of the worker
//! that took over.

use crate::error::StorageResult;

/// The state of a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// The task is waiting for a worker.
    Pending,
    /// A worker owns the task.
    Running,
    /// The task finished successfully.
    Completed,
    /// The task failed.
    Failed,
    /// The task was cancelled.
    Cancelled,
}

impl TaskState {
    /// The name of the state.
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskState::Pending => "pending",
            TaskState::Running => "running",
            TaskState::Completed => "completed",
            TaskState::Failed => "failed",
            TaskState::Cancelled => "cancelled",
        }
    }

    /// Parse a state name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(TaskState::Pending),
            "running" => Some(TaskState::Running),
            "completed" => Some(TaskState::Completed),
            "failed" => Some(TaskState::Failed),
            "cancelled" => Some(TaskState::Cancelled),
            _ => None,
        }
    }

    /// Whether the state is a terminal one.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskState::Completed | TaskState::Failed | TaskState::Cancelled
        )
    }
}

/// One task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    /// The task identifier.
    pub task_id: String,
    /// The principal the task belongs to.
    pub principal: String,
    /// The identity the task runs under.
    pub identity: String,
    /// The worker that owns the task.
    pub owner: Option<String>,
    /// The state of the task.
    pub state: TaskState,
    /// A short progress note.
    pub progress: Option<String>,
    /// A reference to the result, not the result itself.
    pub result_ref: Option<String>,
    /// The fencing token of the current claim.
    pub fencing_token: u64,
    /// When the task was created.
    pub created_at: u64,
    /// When the task last changed.
    pub updated_at: u64,
}

/// The task store.
pub trait TaskStore {
    /// Store a task.
    fn put_task(&self, task: &Task) -> StorageResult<()>;
    /// Look up a task.
    fn get_task(&self, task_id: &str) -> StorageResult<Option<Task>>;
    /// Claim a task for a worker.
    ///
    /// The claim fences off an earlier owner: the returned task carries the
    /// new fencing token, and the earlier worker's token is stale.
    fn claim_task(&self, task_id: &str, owner: &str, now: u64) -> StorageResult<Task>;
    /// Report progress on a task the caller still owns.
    fn set_progress(
        &self,
        task_id: &str,
        owner: &str,
        fencing_token: u64,
        progress: &str,
        now: u64,
    ) -> StorageResult<bool>;
    /// Finish a task the caller still owns.
    fn complete_task(
        &self,
        task_id: &str,
        owner: &str,
        fencing_token: u64,
        result_ref: &str,
        now: u64,
    ) -> StorageResult<bool>;
    /// Fail a task the caller still owns.
    fn fail_task(
        &self,
        task_id: &str,
        owner: &str,
        fencing_token: u64,
        now: u64,
    ) -> StorageResult<bool>;
    /// Cancel a task.
    fn cancel_task(&self, task_id: &str, now: u64) -> StorageResult<bool>;
    /// List the tasks in one state.
    fn list_tasks(&self, state: Option<TaskState>) -> StorageResult<Vec<Task>>;
}
