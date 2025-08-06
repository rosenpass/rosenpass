#![cfg(feature = "tokio")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::sleep;

use rosenpass_util::tokio::janitor::{enter_janitor, spawn_cleanup_job, try_spawn_daemon};

#[tokio::test]
async fn janitor_demo() -> anyhow::Result<()> {
    let count = Arc::new(AtomicUsize::new(0));

    // Make sure the program has access to an ambient janitor
    {
        let count = count.clone();
        enter_janitor(async move {
            let _drop_guard = AsyncDropDemo::new(count.clone()).await;

            // Start a background job
            {
                let count = count.clone();
                try_spawn_daemon(async move {
                    for _ in 0..17 {
                        count.fetch_add(1, Ordering::Relaxed);
                        sleep(Duration::from_micros(200)).await;
                    }
                    Ok(())
                })?;
            }

            // Start another
            {
                let count = count.clone();
                try_spawn_daemon(async move {
                    for _ in 0..6 {
                        count.fetch_add(100, Ordering::Relaxed);
                        sleep(Duration::from_micros(800)).await;
                    }
                    Ok(())
                })?;
            }

            // Note how this function just starts a couple background jobs, but exits immediately

            anyhow::Ok(())
        })
    }
    .await;

    // At this point, all background jobs have finished, now we can check the result of all our
    // additions
    assert_eq!(count.load(Ordering::Acquire), 41617);

    Ok(())
}

/// Demo of how janitor can be used to implement async destructors
struct AsyncDropDemo {
    count: Arc<AtomicUsize>,
}

impl AsyncDropDemo {
    async fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1000, Ordering::Relaxed);
        sleep(Duration::from_micros(50)).await;
        AsyncDropDemo { count }
    }
}

impl Drop for AsyncDropDemo {
    fn drop(&mut self) {
        let count = self.count.clone();
        // This necessarily uses the panicking variant;
        // we use spawn_cleanup_job because this makes more semantic sense in this context
        spawn_cleanup_job(async move {
            for _ in 0..4 {
                count.fetch_add(10000, Ordering::Relaxed);
                sleep(Duration::from_micros(800)).await;
            }
            Ok(())
        })
    }
}
