//! Facilities to spawn tasks that will be reliably executed
//! before the current tokio context finishes.
//!
//! Asynchronous applications often need to manage multiple parallel tasks.
//! Tokio supports spawning these tasks with [tokio::task::spawn], but when the
//! tokio event loop exits, all lingering background tasks will aborted.
//!
//! Tokio supports managing multiple parallel tasks, all of which should exit successfully, through
//! [tokio::task::JoinSet]. This is a useful and very explicit API. To launch a background job,
//! user code needs to be aware of which JoinSet to use, so this can lead to a JoinSet needing to
//! be handed around in many parts of the application.
//!
//! This level of explicitness avoids bugs, but it can be cumbersome to use and it can introduce a
//! [function coloring](https://morestina.net/1686/rust-async-is-colored) issue;
//! creating a strong distinction between functions which have access
//! to a JoinSet (one color) and those that have not (the other color). Functions with the color
//! that has access to a JoinSet can call those functions that do not need access, but not the
//! other way around. This can make refactoring quite difficult: your refactor needs to use a
//! function that requires a JoinSet? Then have fun spending quite a bit of time recoloring
//! possibly many parts of your code base.
//!
//! This module solves this issue by essentially registering a central [JoinSet] through ambient
//! (semi-global), task-local variables. The mechanism to register this task-local JoinSet is
//! [tokio::task_local].
//!
//! # Error-handling
//!
//! The janitor accepts daemons/cleanup jobs which return an [anyhow::Error].
//! When any daemon returns an error, then the entire janitor will immediately exit with a failure
//! without awaiting the other registered tasks.
//!
//! The janitor can generally produce errors in three scenarios:
//!
//! - A daemon panics
//! - A daemon returns an error
//! - An internal error
//!
//! When [enter_janitor]/[ensure_janitor] is used to set up a janitor, these functions will always
//! panic in case of a janitor error. **This also means, that these functions panic if any daemon
//! returns an error**.
//!
//! You can explicitly handle janitor errors through [try_enter_janitor]/[try_ensure_janitor].
//!
//! # Examples
//!
#![doc = "```ignore"]
#![doc = include_str!("../../tests/janitor.rs")]
#![doc = "```"]

use std::any::type_name;
use std::future::Future;

use anyhow::{bail, Context};

use tokio::task::{AbortHandle, JoinError, JoinHandle, JoinSet};
use tokio::task_local;

use tokio::sync::mpsc::unbounded_channel as janitor_channel;

use crate::tokio::local_key::LocalKeyExt;

/// Type for the message queue from [JanitorClient]/[JanitorSupervisor] to [JanitorAgent]: Receiving side
type JanitorQueueRx = tokio::sync::mpsc::UnboundedReceiver<JanitorTicket>;
/// Type for the message queue from [JanitorClient]/[JanitorSupervisor] to [JanitorAgent]: Sending side
type JanitorQueueTx = tokio::sync::mpsc::UnboundedSender<JanitorTicket>;
/// Type for the message queue from [JanitorClient]/[JanitorSupervisor] to [JanitorAgent]: Sending side, Weak reference
type WeakJanitorQueueTx = tokio::sync::mpsc::WeakUnboundedSender<JanitorTicket>;

/// Type of the return value for jobs submitted to [spawn_daemon]/[spawn_cleanup_job]
type CleanupJobResult = anyhow::Result<()>;
/// Handle by which we internally refer to cleanup jobs submitted by [spawn_daemon]/[spawn_cleanup_job]
/// to the current [JanitorAgent]
type CleanupJob = JoinHandle<CleanupJobResult>;

task_local! {
    /// Handle to the current [JanitorAgent]; this is where [ensure_janitor]/[enter_janitor]
    /// register the newly created janitor
    static CURRENT_JANITOR: JanitorClient;
}

/// Messages supported by [JanitorAgent]
#[derive(Debug)]
enum JanitorTicket {
    /// This message transmits a new cleanup job to the [JanitorAgent]
    CleanupJob(CleanupJob),
}

/// Represents the background task which actually manages cleanup jobs.
///
/// This is what is started by [enter_janitor]/[ensure_janitor]
/// and what receives the messages sent by [JanitorSupervisor]/[JanitorClient]
#[derive(Debug)]
struct JanitorAgent {
    /// Background tasks currently registered with this agent.
    ///
    /// This contains two types of tasks:
    ///
    /// 1. Background jobs launched through [enter_janitor]/[ensure_janitor]
    /// 2. A single task waiting for new [JanitorTicket]s being transmitted from a [JanitorSupervisor]/[JanitorClient]
    tasks: JoinSet<AgentInternalEvent>,
    /// Whether this [JanitorAgent] will ever receive new [JanitorTicket]s
    ///
    /// Communication between [JanitorAgent] and [JanitorSupervisor]/[JanitorClient] uses a message
    /// queue (see [JanitorQueueTx]/[JanitorQueueRx]/[WeakJanitorQueueTx]), but you may notice that
    /// the Agent does not actually contain a field storing the message queue.
    /// Instead, to appease the borrow checker, the message queue is moved into the internal
    /// background task (see [Self::tasks]) that waits for new [JanitorTicket]s.
    ///
    /// Since our state machine still needs to know, whether that queue is closed, we maintain this
    /// flag.
    ///
    /// See [AgentInternalEvent::TicketQueueClosed].
    ticket_queue_closed: bool,
}

/// These are the return values (events) returned by [JanitorAgent] internal tasks (see
/// [JanitorAgent::tasks]).
#[derive(Debug)]
enum AgentInternalEvent {
    /// Notifies the [JanitorAgent] state machine that a cleanup job finished successfully
    ///
    /// Sent by genuine background tasks registered through [enter_janitor]/[ensure_janitor].
    CleanupJobSuccessful,
    /// Notifies the [JanitorAgent] state machine that a cleanup job finished with a tokio
    /// [JoinError].
    ///
    /// Sent by genuine background tasks registered through [enter_janitor]/[ensure_janitor].
    CleanupJobJoinError(JoinError),
    /// Notifies the [JanitorAgent] state machine that a cleanup job returned an error.
    ///
    /// Sent by genuine background tasks registered through [enter_janitor]/[ensure_janitor].
    CleanupJobReturnedError(anyhow::Error),
    /// Notifies the [JanitorAgent] state machine that a new cleanup job was received through the
    /// ticket queue.
    ///
    /// Sent by the background task managing the ticket queue.
    ReceivedCleanupJob(JanitorQueueRx, CleanupJob),
    /// Notifies the [JanitorAgent] state machine that a new cleanup job was received through the
    /// ticket queue.
    ///
    /// Sent by the background task managing the ticket queue.
    ///
    /// See [JanitorAgent::ticket_queue_closed].
    TicketQueueClosed,
}

impl JanitorAgent {
    /// Create a new agent. Start with [Self::start].
    fn new() -> Self {
        let tasks = JoinSet::new();
        let ticket_queue_closed = false;
        Self {
            tasks,
            ticket_queue_closed,
        }
    }

    /// Main entry point for the [JanitorAgent]. Launches the background task and returns a [JanitorSupervisor]
    /// which can be used to send tickets to the agent and to wait for agent termination.
    pub async fn start() -> JanitorSupervisor {
        let (queue_tx, queue_rx) = janitor_channel();
        let join_handle = tokio::spawn(async move { Self::new().event_loop(queue_rx).await });
        JanitorSupervisor::new(join_handle, queue_tx)
    }

    /// Event loop, processing events from the ticket queue and from [Self::tasks]
    async fn event_loop(&mut self, queue_rx: JanitorQueueRx) -> anyhow::Result<()> {
        // Seed the internal task list with a single task to receive
        self.spawn_internal_recv_ticket_task(queue_rx).await;

        // Process all incoming events until handle_one_event indicates there are
        // no more events to process
        while self.handle_one_event().await?.is_some() {}

        Ok(())
    }

    /// Process events from [Self::tasks] (and by proxy from the ticket queue)
    ///
    /// This is the agent's main state machine.
    async fn handle_one_event(&mut self) -> anyhow::Result<Option<()>> {
        use AgentInternalEvent as E;
        match (self.tasks.join_next().await, self.ticket_queue_closed) {
            // Normal, successful operation

            // CleanupJob exited successfully, no action neccesary
            (Some(Ok(E::CleanupJobSuccessful)), _) => Ok(Some(())),

            // New cleanup job scheduled, add to task list and wait for another task
            (Some(Ok(E::ReceivedCleanupJob(queue_rx, job))), _) => {
                self.spawn_internal_recv_ticket_task(queue_rx).await;
                self.spawn_internal_cleanup_task(job).await;
                Ok(Some(()))
            }

            // Ticket queue is closed; now we are just waiting for the remaining cleanup jobs
            // to terminate
            (Some(Ok(E::TicketQueueClosed)), _) => {
                self.ticket_queue_closed = true;
                Ok(Some(()))
            }

            // No more tasks in the task manager and the ticket queue is already closed.
            // This just means we are done and can finally terminate the janitor agent
            (Option::None, true) => Ok(None),

            // Error handling

            // User callback errors

            // Some cleanup job returned an error as a result
            (Some(Ok(E::CleanupJobReturnedError(err))), _) => Err(err).with_context(|| {
                format!("Error in cleanup job handled by {}", type_name::<Self>())
            }),

            // JoinError produced by the user task: The user task was cancelled.
            (Some(Ok(E::CleanupJobJoinError(err))), _) if err.is_cancelled() => Err(err).with_context(|| {
                format!(
                    "Error in cleanup job handled by {me}; the cleanup task was cancelled.
                    This should not happend and likely indicates a developer error in {me}.",
                    me = type_name::<Self>()
                )
            }),

            // JoinError produced by the user task: The user task panicked
            (Some(Ok(E::CleanupJobJoinError(err))), _) => Err(err).with_context(|| {
                format!(
                    "Error in cleanup job handled by {}; looks like the cleanup task panicked.",
                    type_name::<Self>()
                )
            }),

            // Internal errors: Internal task error

            // JoinError produced by JoinSet::join_next(): The internal task was cancelled
            (Some(Err(err)), _) if err.is_cancelled() => Err(err).with_context(|| {
                format!(
                    "Internal error in {me}; internal async task was cancelled. \
                    This is probably a developer error in {me}.",
                    me = type_name::<Self>()
                )
            }),

            // JoinError produced by JoinSet::join_next(): The internal task panicked
            (Some(Err(err)), _) => Err(err).with_context(|| {
                format!(
                    "Internal error in {me}; internal async task panicked. \
                    This is probably a developer error in {me}.",
                    me = type_name::<Self>()
                )
            }),


            // Internal errors: State machine failure

            // No tasks left, but ticket queue was not drained
            (Option::None, false) => bail!("Internal error in {me}::handle_one_event(); \
                there are no more internal tasks active, but the ticket queue was not drained. \
                The {me}::handle_one_event() code is deliberately designed to never leave the internal task set empty; \
                instead, there should always be one task to receive new cleanup jobs from the task queue unless the task \
                queue has been closed. \
                This is probably a developer error.",
                me = type_name::<Self>())
        }
    }

    /// Used by [Self::event_loop] and [Self::handle_one_event] to start the internal
    /// task waiting for tickets on the ticket queue.
    async fn spawn_internal_recv_ticket_task(
        &mut self,
        mut queue_rx: JanitorQueueRx,
    ) -> AbortHandle {
        self.tasks.spawn(async {
            use AgentInternalEvent as E;
            use JanitorTicket as T;

            let ticket = queue_rx.recv().await;
            match ticket {
                Some(T::CleanupJob(job)) => E::ReceivedCleanupJob(queue_rx, job),
                Option::None => E::TicketQueueClosed,
            }
        })
    }

    /// Used by [Self::event_loop] and [Self::handle_one_event] to register
    /// background deamons/cleanup jobs submitted via [JanitorTicket]
    async fn spawn_internal_cleanup_task(&mut self, job: CleanupJob) -> AbortHandle {
        self.tasks.spawn(async {
            use AgentInternalEvent as E;
            match job.await {
                Ok(Ok(())) => E::CleanupJobSuccessful,
                Ok(Err(e)) => E::CleanupJobReturnedError(e),
                Err(e) => E::CleanupJobJoinError(e),
            }
        })
    }
}

/// Client for [JanitorAgent]. Allows for [JanitorTicket]s (background jobs)
/// to be transmitted to the current [JanitorAgent].
///
/// This is stored in [CURRENT_JANITOR] as a task.-local variable.
#[derive(Debug)]
struct JanitorClient {
    /// Queue we can use to send messages to the current janitor
    queue_tx: WeakJanitorQueueTx,
}

impl JanitorClient {
    /// Create a new client. Use through [JanitorSupervisor::get_client]
    fn new(queue_tx: WeakJanitorQueueTx) -> Self {
        Self { queue_tx }
    }

    /// Has the associated [JanitorAgent] shut down?
    pub fn is_closed(&self) -> bool {
        self.queue_tx
            .upgrade()
            .map(|channel| channel.is_closed())
            .unwrap_or(false)
    }

    /// Spawn a new cleanup job/daemon with the associated [JanitorAgent].
    ///
    /// Used internally by [spawn_daemon]/[spawn_cleanup_job].
    pub fn spawn_cleanup_task<F>(&self, future: F) -> Result<(), TrySpawnCleanupJobError>
    where
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let background_task = tokio::spawn(future);
        self.queue_tx
            .upgrade()
            .ok_or(TrySpawnCleanupJobError::ActiveJanitorTerminating)?
            .send(JanitorTicket::CleanupJob(background_task))
            .map_err(|_| TrySpawnCleanupJobError::ActiveJanitorTerminating)
    }
}

/// Client for [JanitorAgent]. Allows waiting for [JanitorAgent] termination as well as creating
/// [JanitorClient]s, which in turn can be used to submit background daemons/termination jobs
/// to the agent.
#[derive(Debug)]
struct JanitorSupervisor {
    /// Represents the tokio task associated with the [JanitorAgent].
    ///
    /// We use this to wait for [JanitorAgent] termination in [enter_janitor]/[ensure_janitor]
    agent_join_handle: CleanupJob,
    /// Queue we can use to send messages to the current janitor
    queue_tx: JanitorQueueTx,
}

impl JanitorSupervisor {
    /// Create a new janitor supervisor. Use through [JanitorAgent::start]
    pub fn new(agent_join_handle: CleanupJob, queue_tx: JanitorQueueTx) -> Self {
        Self {
            agent_join_handle,
            queue_tx,
        }
    }

    /// Create a [JanitorClient] for submitting background daemons/cleanup jobs
    pub fn get_client(&self) -> JanitorClient {
        JanitorClient::new(self.queue_tx.clone().downgrade())
    }

    /// Wait for [JanitorAgent] termination
    pub async fn terminate_janitor(self) -> anyhow::Result<()> {
        std::mem::drop(self.queue_tx);
        self.agent_join_handle.await?
    }
}

/// Return value of [try_enter_janitor].
#[derive(Debug)]
pub struct EnterJanitorResult<T, E> {
    /// The result produced by the janitor itself.
    ///
    /// This may contain an error if one of the background daemons/cleanup tasks returned an error,
    /// panicked, or in case there is an internal error in the janitor.
    pub janitor_result: anyhow::Result<()>,
    /// Contains the result of the future passed to [try_enter_janitor].
    pub callee_result: Result<T, E>,
}

impl<T, E> EnterJanitorResult<T, E> {
    /// Create a new result from its components
    pub fn new(janitor_result: anyhow::Result<()>, callee_result: Result<T, E>) -> Self {
        Self {
            janitor_result,
            callee_result,
        }
    }

    /// Turn this named type into a tuple
    pub fn into_tuple(self) -> (anyhow::Result<()>, Result<T, E>) {
        (self.janitor_result, self.callee_result)
    }

    /// Panic if [Self::janitor_result] contains an error; returning [Self::callee_result]
    /// otherwise.
    ///
    /// If this panics and both [Self::janitor_result] and [Self::callee_result] contain an error,
    /// this will print both errors.
    pub fn unwrap_janitor_result(self) -> Result<T, E>
    where
        E: std::fmt::Debug,
    {
        let me: EnsureJanitorResult<T, E> = self.into();
        me.unwrap_janitor_result()
    }

    /// Panic if [Self::janitor_result] or [Self::callee_result] contain an error,
    /// returning the Ok value of [Self::callee_result].
    ///
    /// If this panics and both [Self::janitor_result] and [Self::callee_result] contain an error,
    /// this will print both errors.
    pub fn unwrap(self) -> T
    where
        E: std::fmt::Debug,
    {
        let me: EnsureJanitorResult<T, E> = self.into();
        me.unwrap()
    }
}

/// Return value of [try_ensure_janitor]. The only difference compared to [EnterJanitorResult]
/// is that [Self::janitor_result] contains None in case an ambient janitor had already existed.
#[derive(Debug)]
pub struct EnsureJanitorResult<T, E> {
    /// See [EnterJanitorResult::janitor_result]
    ///
    /// This is:
    ///
    /// - `None` if a pre-existing ambient janitor was used
    /// - `Some(Ok(()))` if a new janitor had to be created and it exited successfully
    /// - `Some(Err(...))` if a new janitor had to be created and it exited with an error
    pub janitor_result: Option<anyhow::Result<()>>,
    /// See [EnterJanitorResult::callee]
    pub callee_result: Result<T, E>,
}

impl<T, E> EnsureJanitorResult<T, E> {
    /// See [EnterJanitorResult::new]
    pub fn new(janitor_result: Option<anyhow::Result<()>>, callee_result: Result<T, E>) -> Self {
        Self {
            janitor_result,
            callee_result,
        }
    }

    /// Sets up a [EnsureJanitorResult] with [EnsureJanitorResult::janitor_result] = None.
    pub fn from_callee_result(callee_result: Result<T, E>) -> Self {
        Self::new(None, callee_result)
    }

    /// Turn this named type into a tuple
    pub fn into_tuple(self) -> (Option<anyhow::Result<()>>, Result<T, E>) {
        (self.janitor_result, self.callee_result)
    }

    /// See [EnterJanitorResult::unwrap_janitor_result]
    ///
    /// If [Self::janitor_result] is None, this won't panic.
    pub fn unwrap_janitor_result(self) -> Result<T, E>
    where
        E: std::fmt::Debug,
    {
        match self.into_tuple() {
            (Some(Ok(())) | None, res) => res,
            (Some(Err(err)), Ok(_)) => panic!(
                "Callee in enter_janitor()/ensure_janitor() was successful, \
                but the janitor or some of its deamons failed: {err:?}"
            ),
            (Some(Err(jerr)), Err(cerr)) => panic!(
                "Both the calee and the janitor or \
                some of its deamons falied in enter_janitor()/ensure_janitor():\n\
                \n\
                Janitor/Daemon error: {jerr:?}
                \n\
                Callee error: {cerr:?}"
            ),
        }
    }

    /// See [EnterJanitorResult::unwrap]
    ///
    /// If [Self::janitor_result] is None, this is not considered a failure.
    pub fn unwrap(self) -> T
    where
        E: std::fmt::Debug,
    {
        match self.unwrap_janitor_result() {
            Ok(val) => val,
            Err(err) => panic!(
                "Janitor or and its deamons in in enter_janitor()/ensure_janitor() was successful, \
                but the callee itself failed: {err:?}"
            ),
        }
    }
}

impl<T, E> From<EnterJanitorResult<T, E>> for EnsureJanitorResult<T, E> {
    fn from(val: EnterJanitorResult<T, E>) -> Self {
        EnsureJanitorResult::new(Some(val.janitor_result), val.callee_result)
    }
}

/// Non-panicking version of [enter_janitor].
pub async fn try_enter_janitor<T, E, F>(future: F) -> EnterJanitorResult<T, E>
where
    T: 'static,
    F: Future<Output = Result<T, E>> + 'static,
{
    let janitor_handle = JanitorAgent::start().await;
    let callee_result = CURRENT_JANITOR
        .scope(janitor_handle.get_client(), future)
        .await;
    let janitor_result = janitor_handle.terminate_janitor().await;
    EnterJanitorResult::new(janitor_result, callee_result)
}

/// Non-panicking version of [ensure_janitor]
pub async fn try_ensure_janitor<T, E, F>(future: F) -> EnsureJanitorResult<T, E>
where
    T: 'static,
    F: Future<Output = Result<T, E>> + 'static,
{
    match CURRENT_JANITOR.is_set() {
        true => EnsureJanitorResult::from_callee_result(future.await),
        false => try_enter_janitor(future).await.into(),
    }
}

/// Register a janitor that can be used to register background daemons/cleanup jobs **only within
/// the future passed to this**.
///
/// The function will wait for both the given future and all background jobs registered with the
/// janitor to terminate.
///
/// For a version that does not panick, see [try_enter_janitor].
pub async fn enter_janitor<T, E, F>(future: F) -> Result<T, E>
where
    T: 'static,
    E: std::fmt::Debug,
    F: Future<Output = Result<T, E>> + 'static,
{
    try_enter_janitor(future).await.unwrap_janitor_result()
}

/// Variant of [enter_janitor] that will first check if a janitor already exists.
/// A new janitor is only set up, if no janitor has been previously registered.
pub async fn ensure_janitor<T, E, F>(future: F) -> Result<T, E>
where
    T: 'static,
    E: std::fmt::Debug,
    F: Future<Output = Result<T, E>> + 'static,
{
    try_ensure_janitor(future).await.unwrap_janitor_result()
}

/// Error returned by [try_spawn_cleanup_job]
#[derive(thiserror::Error, Debug)]
pub enum TrySpawnCleanupJobError {
    /// No active janitor exists
    #[error("No janitor registered. Did the developer forget to call enter_janitor(…) or ensure_janitor(…)?")]
    NoActiveJanitor,
    /// The currently active janitor is in the process of terminating
    #[error("There is a registered janitor, but it is currently in the process of terminating and won't accept new tasks.")]
    ActiveJanitorTerminating,
}

/// Check whether a janitor has been set up with [enter_janitor]/[ensure_janitor]
pub fn has_active_janitor() -> bool {
    CURRENT_JANITOR
        .try_with(|client| client.is_closed())
        .unwrap_or(false)
}

/// Non-panicking variant of [spawn_cleanup_job].
///
/// This function is available under two names; see [spawn_cleanup_job] for details about this:
///
/// 1. [try_spawn_cleanup_job]
/// 2. [try_spawn_daemon]
pub fn try_spawn_cleanup_job<F>(future: F) -> Result<(), TrySpawnCleanupJobError>
where
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    CURRENT_JANITOR
        .try_with(|client| client.spawn_cleanup_task(future))
        .map_err(|_| TrySpawnCleanupJobError::NoActiveJanitor)??;
    Ok(())
}

/// Register a cleanup job or a daemon with the current janitor registered through
/// [enter_janitor]/[ensure_janitor]:
///
/// This function is available under two names:
///
/// 1. [spawn_cleanup_job]
/// 2. [spawn_daemon]
///
/// The first name should be used in destructors and to spawn cleanup actions which immediately
/// begin their task.
///
/// The second name should be used for any other tasks; e.g. when the janitor setup is used to
/// manage multiple parallel jobs, all of which must be waited for.
pub fn spawn_cleanup_job<F>(future: F)
where
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    if let Err(e) = try_spawn_cleanup_job(future) {
        panic!("Could not spawn cleanup job/daemon: {e:?}");
    }
}

pub use spawn_cleanup_job as spawn_daemon;
pub use try_spawn_cleanup_job as try_spawn_daemon;
