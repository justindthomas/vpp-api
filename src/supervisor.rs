//! Connection supervisor for `VppClient`.
//!
//! VPP can crash, restart, or be reconfigured underneath a long-running
//! daemon. The bare `VppClient` doesn't survive that — its socket goes
//! to EOF, the reader loop exits, and every subsequent RPC fails. The
//! supervisor wraps a single `VppClient` and gives daemons a stable
//! handle that survives reconnects:
//!
//! 1. `VppSupervisor::spawn(socket_path)` returns immediately with a
//!    handle. A background task tries to connect, retrying with
//!    exponential backoff until VPP is reachable. It then publishes the
//!    live client through a `watch::Sender<Option<Arc<VppClient>>>`.
//! 2. Daemons obtain the live client with `client().await` (waits if
//!    we're between connections) or `try_client()` (fast non-blocking).
//! 3. On every successful (re)connect the supervisor emits a
//!    `VppLifecycle::Connected { generation }` lifecycle event on a
//!    broadcast channel. A monotonically-increasing generation lets
//!    consumers detect they raced a disconnect even if their tasks
//!    were busy through the dead window.
//! 4. When the live client's reader loop exits (VPP went away), the
//!    supervisor emits `VppLifecycle::Disconnected`, drops the client,
//!    and reconnects.
//!
//! # Per-daemon re-init
//!
//! VPP rebuilds its state from scratch on restart — interface indexes
//! shuffle, the FIB is empty, punt registrations are gone. Each
//! consumer registers a *re-init closure* that runs on every
//! `Connected` event. Typical things a re-init does:
//!
//! - re-fetch interface table (sw_if_index → name)
//! - re-program the FIB from in-memory state (RIB-owning daemons)
//! - re-register punt sockets / event subscriptions
//!
//! The supervisor does **not** call the closure during the very first
//! connect — that's the daemon's normal boot path. Only on subsequent
//! reconnects does the closure fire. This avoids double-running the
//! daemon's normal initialisation.
//!
//! # Backoff
//!
//! Reconnect delay starts at 500 ms and doubles up to 30 s, with light
//! jitter to avoid thundering-herd on a shared VPP restart.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, watch, Mutex};
use tokio::task::JoinHandle;

use crate::client::VppClient;
use crate::error::VppError;

/// Lifecycle event emitted by the supervisor on a broadcast channel.
#[derive(Debug, Clone)]
pub enum VppLifecycle {
    /// A live VPP connection is now available. `generation` increases
    /// monotonically across the supervisor's lifetime — a consumer
    /// can compare it against the last value it saw to detect a
    /// reconnect that happened while it wasn't listening.
    Connected { generation: u64 },
    /// The previous connection was lost; the supervisor is in the
    /// middle of reconnecting. RPCs against any cached `Arc<VppClient>`
    /// the consumer kept will start failing immediately.
    Disconnected,
}

type ReinitFut = Pin<Box<dyn Future<Output = Result<(), VppError>> + Send>>;
type ReinitFn = Box<dyn Fn(Arc<VppClient>, u64) -> ReinitFut + Send + Sync>;

/// Handle to a self-reconnecting VPP API connection.
///
/// Cheap to clone — internally just an `Arc`.
#[derive(Clone)]
pub struct VppSupervisor {
    inner: Arc<Inner>,
}

struct Inner {
    socket_path: String,
    /// Live client (None while we're between connections). Daemons
    /// observe this via `watch` to wait until a connection is up.
    live: watch::Sender<Option<Arc<VppClient>>>,
    live_rx: watch::Receiver<Option<Arc<VppClient>>>,
    /// Lifecycle broadcast — Connected/Disconnected.
    lifecycle: broadcast::Sender<VppLifecycle>,
    /// Strictly-increasing generation number, bumped on every successful
    /// (re)connect. Lets consumers tell whether the client they're
    /// holding still corresponds to the current connection.
    generation: AtomicU64,
    /// Re-init closures registered by daemons. Run on every reconnect
    /// (not the initial connect — that's the daemon's normal boot).
    reinit: Mutex<Vec<ReinitFn>>,
    /// Background supervise task; aborted on drop of the last clone
    /// of the supervisor.
    _task: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Ok(mut guard) = self._task.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

impl VppSupervisor {
    /// Spawn a supervisor that connects to the given socket and
    /// reconnects automatically. Returns immediately — the first
    /// connection happens asynchronously. Use `wait_ready` if you
    /// need to block until a connection is up.
    pub fn spawn(socket_path: impl Into<String>) -> Self {
        let socket_path = socket_path.into();
        let (live_tx, live_rx) = watch::channel(None);
        let (lifecycle_tx, _) = broadcast::channel(64);
        let inner = Arc::new(Inner {
            socket_path: socket_path.clone(),
            live: live_tx,
            live_rx,
            lifecycle: lifecycle_tx,
            generation: AtomicU64::new(0),
            reinit: Mutex::new(Vec::new()),
            _task: Mutex::new(None),
        });
        let task = tokio::spawn(supervise_loop(inner.clone()));
        // Stash the handle so Drop on the final Arc aborts the task.
        // try_lock is fine here — we just created the inner, nothing
        // else holds the lock.
        if let Ok(mut guard) = inner._task.try_lock() {
            *guard = Some(task);
        }
        VppSupervisor { inner }
    }

    /// Subscribe to lifecycle events. The returned receiver only sees
    /// events emitted *after* subscription — call this before kicking
    /// off your re-init logic if you can't afford to miss the first
    /// reconnect.
    pub fn subscribe(&self) -> broadcast::Receiver<VppLifecycle> {
        self.inner.lifecycle.subscribe()
    }

    /// Register a re-init closure that runs on every reconnect (not
    /// the initial connect). The closure receives the new live client
    /// and the new generation number. If it returns an error, the
    /// supervisor logs and continues — a failed re-init does not
    /// trigger another reconnect on its own.
    pub async fn on_reconnect<F, Fut>(&self, f: F)
    where
        F: Fn(Arc<VppClient>, u64) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), VppError>> + Send + 'static,
    {
        let boxed: ReinitFn = Box::new(move |c, g| Box::pin(f(c, g)));
        self.inner.reinit.lock().await.push(boxed);
    }

    /// Returns the live client if one is currently connected, or
    /// `None` if the supervisor is between connections. Non-blocking.
    pub fn try_client(&self) -> Option<Arc<VppClient>> {
        self.inner.live_rx.borrow().clone()
    }

    /// Returns the live client, waiting if currently disconnected.
    /// Useful at the top of every RPC path — daemons that want to
    /// fail-fast during an outage should use `try_client` instead.
    pub async fn client(&self) -> Arc<VppClient> {
        let mut rx = self.inner.live_rx.clone();
        loop {
            if let Some(c) = rx.borrow().clone() {
                if !c.is_closed() {
                    return c;
                }
            }
            // Either no client yet or the cached one already saw EOF.
            // Wait for the watch to change.
            if rx.changed().await.is_err() {
                // Sender dropped — supervisor is gone. Caller will
                // notice via subsequent error paths; just yield.
                tokio::task::yield_now().await;
            }
        }
    }

    /// Wait until at least one connection has been established.
    /// Useful in daemon `main` to gate startup on VPP being reachable.
    pub async fn wait_ready(&self) -> Arc<VppClient> {
        self.client().await
    }

    /// Current generation number — monotonically increasing across the
    /// supervisor's lifetime, bumped once per successful (re)connect.
    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    /// The socket path this supervisor is watching.
    pub fn socket_path(&self) -> &str {
        &self.inner.socket_path
    }
}

/// Backoff schedule: 500 ms, 1 s, 2 s, 4 s, 8 s, 16 s, then 30 s cap.
/// `attempt` is 0 for the first failure, 1 for the second, etc.
fn backoff_delay(attempt: u32) -> Duration {
    let base_ms = 500u64.saturating_mul(1u64 << attempt.min(6));
    let capped_ms = base_ms.min(30_000);
    // Light jitter (±15%) to desync simultaneous reconnect storms.
    let jitter_pct = jitter_15();
    let jittered = (capped_ms as i64 * (100 + jitter_pct as i64)) / 100;
    Duration::from_millis(jittered.max(50) as u64)
}

/// Cheap deterministic-ish jitter without pulling in `rand`.
/// Returns a value in roughly [-15, +15].
fn jitter_15() -> i32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    ((nanos as i32) % 31) - 15
}

async fn supervise_loop(inner: Arc<Inner>) {
    let mut attempt: u32 = 0;
    let mut first = true;
    loop {
        match VppClient::connect(&inner.socket_path).await {
            Ok(client) => {
                attempt = 0;
                let generation = inner.generation.fetch_add(1, Ordering::AcqRel) + 1;
                let arc = Arc::new(client);
                tracing::info!(
                    socket = %inner.socket_path,
                    generation,
                    first,
                    "VPP supervisor connected"
                );
                let _ = inner.live.send(Some(arc.clone()));
                let _ = inner.lifecycle.send(VppLifecycle::Connected { generation });

                if !first {
                    // Run re-init closures. Failures are logged but not
                    // fatal — a daemon that fails to re-program its
                    // state will likely fail its next RPC and the user
                    // will see it; we don't want a buggy closure to
                    // wedge the supervisor in a tight reconnect loop.
                    let closures = inner.reinit.lock().await;
                    for (i, closure) in closures.iter().enumerate() {
                        if let Err(e) = closure(arc.clone(), generation).await {
                            tracing::error!(
                                closure_idx = i,
                                generation,
                                error = %e,
                                "VPP supervisor re-init closure failed"
                            );
                        }
                    }
                }
                first = false;

                // Wait for this client's reader loop to exit.
                let mut signal = arc.closed_signal();
                // The signal starts at `false`; flip happens when reader
                // exits. If it's already flipped (lost the race), the
                // changed() returns immediately on next poll.
                loop {
                    if *signal.borrow() {
                        break;
                    }
                    if signal.changed().await.is_err() {
                        // Sender dropped without flipping — shouldn't
                        // happen, the ClosedGuard always fires. Treat
                        // as disconnect.
                        break;
                    }
                }

                tracing::warn!(
                    socket = %inner.socket_path,
                    generation,
                    "VPP supervisor: connection lost, reconnecting"
                );
                let _ = inner.live.send(None);
                let _ = inner.lifecycle.send(VppLifecycle::Disconnected);
                // Drop our reference; if no consumer is holding the
                // client it's freed here.
                drop(arc);
                // Fall through to reconnect.
            }
            Err(e) => {
                let delay = backoff_delay(attempt);
                if attempt == 0 {
                    tracing::warn!(
                        socket = %inner.socket_path,
                        error = %e,
                        retry_in_ms = delay.as_millis() as u64,
                        "VPP supervisor: initial connect failed, will retry"
                    );
                } else {
                    tracing::debug!(
                        socket = %inner.socket_path,
                        attempt,
                        error = %e,
                        retry_in_ms = delay.as_millis() as u64,
                        "VPP supervisor: reconnect attempt failed"
                    );
                }
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_then_caps() {
        let d0 = backoff_delay(0).as_millis();
        let d3 = backoff_delay(3).as_millis();
        let d10 = backoff_delay(10).as_millis();
        // d0 ≈ 500ms ±15%, d3 ≈ 4000ms ±15%, d10 cap 30000ms ±15%.
        assert!(d0 < 700);
        assert!(d3 > 2000 && d3 < 5000);
        assert!(d10 > 25_000 && d10 < 35_000);
    }
}
