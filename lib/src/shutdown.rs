//! Graceful shutdown notifications and completion tracking.

use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

/// This entity is intended to provide a possibility to gracefully shutdown
/// an async operation.
/// The usage is like the following:
///
/// * on the application side:
/// ```text
/// let shutdown = Shutdown::new();
/// ...
/// shutdown.lock().unwrap().submit();
/// shutdown.lock().unwrap().completion().await;
/// ```
///
/// * inside the library:
/// ```text
/// let (mut shutdown_notification, _shutdown_completion) = {
///     let shutdown = self.shutdown.lock().unwrap();
///     (shutdown.notification_handler(), shutdown.completion_guard())
/// };
/// tokio::select! {
///     x = shutdown_notification.wait() => {
///         match x {
///             Ok(_) => Ok(()), // do graceful things
///             Err(e) => Err(...),
///         }
///     }
///     _ = another.await => Ok(()),
/// }
/// ```
#[derive(Debug)]
pub struct Shutdown {
    /// Sends messages to [`Notification::notify_rx`]
    notify_tx: broadcast::Sender<()>,
    /// Protects [`Shutdown::completion`] from early return
    completion_rx: mpsc::Receiver<()>,
    /// Protects [`Shutdown::completion`] from early return
    completion_tx: Option<mpsc::Sender<()>>,
}

#[derive(Debug)]
pub(crate) struct Notification {
    /// Receives messages from [`Shutdown::notify_tx`]
    notify_rx: broadcast::Receiver<()>,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub(crate) enum NotificationError {
    Closed,
}

/// Protects [`Shutdown::completion`] from early return
#[derive(Debug)]
pub(crate) struct CompletionGuard {
    _completion_tx: mpsc::Sender<()>,
}

impl Shutdown {
    /// Create a shared shutdown coordinator.
    #[must_use]
    pub fn new() -> Arc<Mutex<Self>> {
        let (notify_tx, _) = broadcast::channel(1);
        let (completion_tx, completion_rx) = mpsc::channel(1);

        Arc::new(Mutex::new(Self {
            notify_tx,
            completion_rx,
            completion_tx: Some(completion_tx),
        }))
    }

    /// Tell the things to do graceful shutdowns. See `Notification::wait()`.
    pub fn submit(&self) {
        if let Err(e) = self.notify_tx.send(()) {
            debug!("Failed to submit: {e}");
        }
    }

    /// Wait until all the things commit graceful shutdowns
    pub async fn completion(&mut self) {
        self.completion_tx = None;
        // receiver returns `None` after all the senders are dropped
        let _ = self.completion_rx.recv().await;
    }

    /// Get a completion handler which is used to notify the application level of
    /// the shutdown completion. The application is notified right after the guard
    /// is dropped.
    /// May return [`None`] in case shutdown has already been committed.
    pub(crate) fn completion_guard(&self) -> Option<CompletionGuard> {
        self.completion_tx
            .clone()
            .map(|completion_tx| CompletionGuard {
                _completion_tx: completion_tx,
            })
    }

    /// Get a notification handler which is used to initiate graceful shutdowns
    /// in the things from the application level
    pub(crate) fn notification_handler(&self) -> Notification {
        Notification {
            notify_rx: self.notify_tx.subscribe(),
        }
    }
}

impl Notification {
    /// Wait for a notification from the application level to initiate a graceful shutdown
    pub(crate) async fn wait(&mut self) -> Result<(), NotificationError> {
        loop {
            match self.notify_rx.recv().await {
                Ok(()) => break Ok(()),
                Err(broadcast::error::RecvError::Lagged(_)) => (),
                Err(broadcast::error::RecvError::Closed) => break Err(NotificationError::Closed),
            }
        }
    }
}

impl Display for NotificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "Channel closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::shutdown::Shutdown;
    use std::io;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn test() {
        let result = async {
            let shutdown = Shutdown::new();
            let (mut notification, completion_guard, final_guard) = {
                let shutdown = shutdown
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                (
                    shutdown.notification_handler(),
                    shutdown.completion_guard(),
                    shutdown.completion_guard(),
                )
            };
            let task = tokio::spawn(async move {
                let result = notification.wait().await;
                drop(completion_guard);
                result
            });
            shutdown
                .lock()
                .map_err(|e| io::Error::other(e.to_string()))?
                .submit();
            let mut shutdown = Arc::try_unwrap(shutdown)
                .map_err(|_| io::Error::other("Shutdown coordinator is still shared"))?
                .into_inner()
                .map_err(|e| io::Error::other(e.to_string()))?;
            let (pending, completed) = {
                let completion = shutdown.completion();
                tokio::pin!(completion);
                let pending = futures::poll!(completion.as_mut()).is_pending();
                drop(final_guard);
                (
                    pending,
                    tokio::time::timeout(Duration::from_secs(5), completion).await,
                )
            };
            Ok::<_, Box<dyn std::error::Error>>((
                pending,
                completed,
                task.await?,
                shutdown.completion_guard().is_none(),
            ))
        }
        .await;
        assert!(
            matches!(result, Ok((true, Ok(()), Ok(()), true))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn lagged_notification_still_requests_shutdown() {
        let result = async {
            let shutdown = Shutdown::new();
            let mut notification = {
                let shutdown = shutdown
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let notification = shutdown.notification_handler();
                shutdown.submit();
                shutdown.submit();
                notification
            };
            let notified = notification.wait().await;
            drop(shutdown);
            Ok::<_, io::Error>((notified, notification.wait().await))
        }
        .await;
        assert!(
            matches!(result, Ok((Ok(()), Err(super::NotificationError::Closed)))),
            "{result:?}"
        );
    }
}
