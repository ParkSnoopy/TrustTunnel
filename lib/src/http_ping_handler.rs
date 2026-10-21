use crate::http_codec::HttpCodec;
use crate::shutdown::Shutdown;
use crate::{log_id, log_utils};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub async fn listen(
    shutdown: Arc<Mutex<Shutdown>>,
    mut codec: Box<dyn HttpCodec>,
    timeout: Duration,
    log_id: log_utils::IdChain<u64>,
) {
    let (mut shutdown_notification, _shutdown_completion) = {
        let shutdown = shutdown.lock().unwrap_or_else(|e| {
            log_id!(error, log_id, "Recovering poisoned shutdown lock: {}", e);
            e.into_inner()
        });
        (shutdown.notification_handler(), shutdown.completion_guard())
    };

    let listen_task = async {
        match codec.listen().await {
            Ok(Some(x)) => {
                log_id!(
                    trace,
                    log_id,
                    "Received request: {:?}",
                    x.request().request()
                );
                if let Err(e) = x.split().1.send_ok_response(true) {
                    log_id!(debug, log_id, "Failed to send ping response: {}", e);
                }
            }
            Ok(None) => log_id!(debug, log_id, "Connection closed before any request"),
            Err(e) => log_id!(debug, log_id, "Session error: {}", e),
        }
    };

    tokio::select! {
        x = shutdown_notification.wait() => {
            match x {
                Ok(()) => (),
                Err(e) => log_id!(debug, log_id, "Shutdown notification failure: {}", e),
            }
        },
        () = listen_task => (),
        () = tokio::time::sleep(timeout) => log_id!(debug, log_id, "Session timed out"),
    }

    if let Err(e) = codec.graceful_shutdown().await {
        log_id!(debug, log_id, "Failed to shut down session: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_codec;
    use crate::tls_demultiplexer::Protocol;
    use crate::utils::check;
    use async_trait::async_trait;
    use std::future::Future;
    use std::io;
    use std::task::Context;
    use tokio::sync::oneshot;

    struct BlockingCodec {
        listen_started: Option<oneshot::Sender<()>>,
        shutdown_started: Option<oneshot::Sender<()>>,
        finish_shutdown: oneshot::Receiver<()>,
    }

    #[async_trait]
    impl HttpCodec for BlockingCodec {
        async fn listen(&mut self) -> io::Result<Option<Box<dyn http_codec::Stream>>> {
            if let Some(started) = self.listen_started.take() {
                started
                    .send(())
                    .map_err(|()| io::Error::other("Listen observer closed"))?;
            }
            futures::future::pending().await
        }

        async fn graceful_shutdown(&mut self) -> io::Result<()> {
            if let Some(started) = self.shutdown_started.take() {
                started
                    .send(())
                    .map_err(|()| io::Error::other("Shutdown observer closed"))?;
            }
            (&mut self.finish_shutdown)
                .await
                .map_err(|e| io::Error::other(e.to_string()))
        }

        fn protocol(&self) -> Protocol {
            Protocol::Http1
        }
    }

    fn completion_pending(shutdown: &Mutex<Shutdown>) -> io::Result<bool> {
        let mut shutdown = shutdown
            .lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        let pending = {
            let completion = shutdown.completion();
            tokio::pin!(completion);
            completion
                .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
                .is_pending()
        };
        drop(shutdown);
        Ok(pending)
    }

    #[tokio::test]
    async fn shutdown_and_timeout_keep_completion_guard_through_graceful_shutdown(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for request_shutdown in [true, false] {
            let shutdown = Shutdown::new();
            let (listen_started, listening) = oneshot::channel();
            let (shutdown_started, shutting_down) = oneshot::channel();
            let (finish_shutdown, finished) = oneshot::channel();
            let task = tokio::spawn(listen(
                shutdown.clone(),
                Box::new(BlockingCodec {
                    listen_started: Some(listen_started),
                    shutdown_started: Some(shutdown_started),
                    finish_shutdown: finished,
                }),
                if request_shutdown {
                    Duration::from_secs(60)
                } else {
                    Duration::ZERO
                },
                log_utils::IdChain::empty(),
            ));
            if request_shutdown {
                tokio::time::timeout(Duration::from_secs(5), listening).await??;
                shutdown
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?
                    .submit();
            }
            tokio::time::timeout(Duration::from_secs(5), shutting_down).await??;
            check(
                completion_pending(&shutdown)?,
                "Shutdown completion returned before graceful shutdown finished",
            )?;
            finish_shutdown
                .send(())
                .map_err(|()| io::Error::other("Graceful shutdown was cancelled"))?;
            tokio::time::timeout(Duration::from_secs(5), task).await??;
            check(
                !completion_pending(&shutdown)?,
                "Shutdown completion guard was not released after graceful shutdown",
            )?;
        }
        Ok(())
    }
}
