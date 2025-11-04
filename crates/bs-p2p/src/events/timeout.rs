//! Time over events
use std::future::Future;

use web_time::Duration;

#[cfg(target_arch = "wasm32")]
pub(crate) async fn delay(duration: Duration) {
    use wasm_bindgen_futures::JsFuture;
    use web_sys::js_sys;

    let millis = duration.as_millis() as f64;
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        let window = web_sys::window().unwrap();
        window
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis as i32)
            .unwrap();
    });

    JsFuture::from(promise).await.unwrap();
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn delay(duration: Duration) {
    tokio::time::sleep(duration).await;
}

// Generic timeout wrapper
pub(crate) async fn with_timeout<F, T>(
    future: F,
    timeout_duration: Duration,
) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    use futures::future::{select, Either};
    use futures::pin_mut;

    let timeout_future = delay(timeout_duration);

    pin_mut!(future);
    pin_mut!(timeout_future);

    match select(future, timeout_future).await {
        Either::Left((result, _)) => Ok(result),
        Either::Right((_, _)) => Err(TimeoutError),
    }
}

#[derive(Debug)]
pub struct TimeoutError;

impl std::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Operation timed out")
    }
}

impl std::error::Error for TimeoutError {}
