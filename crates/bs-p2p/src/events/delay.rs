//! Delay implementation using futures_timer::Delay.
use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};
use web_time::Duration;

use futures::{future::FusedFuture, Future, FutureExt};

/// We need to wrap futures_timer::Delay in a newtype to implement futures::future::FusedFuture so
/// we can use futures::select! macro.
#[derive(Debug)]
pub struct Delay {
    inner: futures_timer::Delay,
    active: bool,
}

impl Delay {
    /// Creates a new Delay which will fire after the given duration.
    pub fn new(duration: Duration) -> Self {
        Self {
            inner: futures_timer::Delay::new(duration),
            active: true,
        }
    }

    /// Stops the Delay from firing.
    pub fn stop(&mut self) {
        self.active = false;
    }

    /// Restarts the Delay.
    pub fn start(&mut self, duration: Duration) {
        match self.active {
            true => {
                self.inner.reset(duration);
            }
            false => {
                self.active = true;
                self.inner.reset(duration);
            }
        }
    }
}

impl Deref for Delay {
    type Target = futures_timer::Delay;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Delay {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Future for Delay {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.active {
            self.inner.poll_unpin(cx)
        } else {
            Poll::Pending
        }
    }
}

impl FusedFuture for Delay {
    fn is_terminated(&self) -> bool {
        !self.active
    }
}
