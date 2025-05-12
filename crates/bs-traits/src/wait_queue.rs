// SPDX-License-Identifier: FSL-1.1
// Handles async wait queues w/o needing to import all of `tokio`
// but is otherwise identical and efficient

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Condvar, Mutex,
    },
    task::{Context, Poll, Waker},
    thread,
};

/// [`ASYNC`] indicates that the referenced instance corresponds to an async operation
const ASYNC: usize = 1;

/// [`WaitQueue`] implements an unfair wait queue.
/// Allows consumers to provide synchronous and asynchronous methods w/o
/// having to use tokio::block_in_place or similar.
///
/// The sole purpose of this is to avoid busy-waiting.
/// The [`AtomicUsize`] is used to track the pointer value of the actual
/// wait queue entry and a flag indicating that the entry is async.
#[derive(Debug, Default)]
pub struct WaitQueue(AtomicUsize);

#[allow(clippy::result_unit_err)]
impl WaitQueue {
    #[inline]
    pub fn wait_sync<T, F: FnOnce() -> Result<T, ()>>(&self, f: F) -> Result<T, ()> {
        let mut current = self.0.load(Ordering::Relaxed);
        let mut entry = SyncWait::new(current);
        let mut entry_mut = Pin::new(&mut entry);

        while let Err(actual) = self.0.compare_exchange_weak(
            current,
            entry_mut.as_mut().get_mut() as *mut SyncWait as usize,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            current = actual;
            entry_mut.next.store(current, Ordering::Relaxed);
        }

        let result = f();
        if result.is_ok() {
            self.signal();
        }

        entry_mut.wait();
        result
    }

    #[inline]
    pub fn push_async_entry<T, F: FnOnce() -> Result<T, ()>>(
        &self,
        async_wait: &mut AsyncWait,
        f: F,
    ) -> Result<T, ()> {
        let mut current = self.0.load(Ordering::Relaxed);
        let wait_queue_ref: &WaitQueue = self;
        async_wait.next.store(current, Ordering::Relaxed);
        async_wait.mutex.replace(Mutex::new((
            Some(unsafe { std::mem::transmute::<&WaitQueue, &WaitQueue>(wait_queue_ref) }),
            None,
        )));

        while let Err(actual) = self.0.compare_exchange_weak(
            current,
            (async_wait as *mut AsyncWait as usize) | ASYNC,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            current = actual;
            async_wait.next.store(current, Ordering::Relaxed);
        }

        if let Ok(result) = f() {
            self.signal();
            if async_wait.try_wait() {
                async_wait.mutex.take();
                return Ok(result);
            }
            // Another task is waking up `async_wait`: dispose of `result` which holds
            // the resource
        }

        // The caller has to await.
        Err(())
    }

    #[inline]
    pub fn signal(&self) {
        let mut current = self.0.swap(0, Ordering::AcqRel);

        // Flip queue to prioritize oldest entries
        let mut prev = 0;
        while (current & (!ASYNC)) != 0 {
            current = if (current & ASYNC) == 0 {
                // synchronous
                let entry_ptr = current as *const SyncWait;
                let next = unsafe {
                    let next = (*entry_ptr).next.load(Ordering::Relaxed);
                    (*entry_ptr).next.store(prev, Ordering::Relaxed);
                    next
                };
                prev = current;
                next
            } else {
                // asynchronous
                let entry_ptr = (current & (!ASYNC)) as *const AsyncWait;
                let next = unsafe {
                    let next = (*entry_ptr).next.load(Ordering::Relaxed);
                    (*entry_ptr).next.store(prev, Ordering::Relaxed);
                    next
                };
                prev = current;
                next
            };
        }

        current = prev;
        while (current & (!ASYNC)) != 0 {
            current = if (current & ASYNC) == 0 {
                // synchronous
                let entry_ptr = current as *const SyncWait;
                unsafe {
                    let next = (*entry_ptr).next.load(Ordering::Relaxed);
                    (*entry_ptr).signal();
                    next
                }
            } else {
                // asynchronous
                let entry_ptr = (current & (!ASYNC)) as *const AsyncWait;
                unsafe {
                    let next = (*entry_ptr).next.load(Ordering::Relaxed);
                    (*entry_ptr).signal();
                    next
                }
            };
        }
    }
}

// Not sure why clippy flags this as dead code?
#[allow(dead_code)]
/// [`DeriveAsyncWait`] derives a mutable reference to [`AsyncWait`].
pub(crate) trait DeriveAsyncWait {
    /// Returns a mutable reference to [`AsyncWait`] if available.
    fn derive(&mut self) -> Option<&mut AsyncWait>;
}

impl DeriveAsyncWait for Pin<&mut AsyncWait> {
    #[inline]
    fn derive(&mut self) -> Option<&mut AsyncWait> {
        unsafe { Some(self.as_mut().get_unchecked_mut()) }
    }
}

impl DeriveAsyncWait for () {
    #[inline]
    fn derive(&mut self) -> Option<&mut AsyncWait> {
        None
    }
}

/// [`AsyncWait`] is inserted into [`WaitQueue`] for the caller to asynchronously wait until signaled.
///
/// [`AsyncWait`] must be pinned outside to be used correctly. The type is [`Unpin`],
/// therefore it can be moved, however, the [`DeriveAsyncWait`] trait forces [`AsyncWait`]
/// to be pinned.
#[derive(Debug, Default)]
pub struct AsyncWait {
    next: AtomicUsize,
    mutex: Option<Mutex<(Option<&'static WaitQueue>, Option<Waker>)>>,
}

impl AsyncWait {
    fn signal(&self) {
        let Some(mutex) = self.mutex.as_ref() else {
            unreachable!();
        };
        if let Ok(mut locked) = mutex.lock() {
            // Disassociate from the wait queue
            locked.0.take();
            if let Some(waker) = locked.1.take() {
                waker.wake();
            }
        }
    }

    fn try_wait(&self) -> bool {
        if let Some(mutex) = self.mutex.as_ref() {
            if let Ok(locked) = mutex.lock() {
                if locked.0.is_none() {
                    // The wait queue entry is not associated with any [`WaitQueue`]
                    return true;
                }
            }
        }
        false
    }

    fn pull(&self) {
        let wait_queue = if let Some(mutex) = self.mutex.as_ref() {
            if let Ok(locked) = mutex.lock() {
                locked.0
            } else {
                None
            }
        } else {
            None
        };
        if let Some(wait_queue) = wait_queue {
            wait_queue.signal();

            // Data race with another thread
            // - Another thread pulls `self` from the `WaitQueue` to send a signal
            // - This thread completes `wait_queue.signal()` which does not contain `self`
            // - This thread drops `self`
            // - The other thread reads `self`

            while !self.try_wait() {
                thread::yield_now();
            }
        }
    }
}

impl Drop for AsyncWait {
    #[inline]
    fn drop(&mut self) {
        if self.mutex.is_some() {
            self.pull();
        }
    }
}

impl Future for AsyncWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(mutex) = self.mutex.as_ref() {
            if let Ok(mut locked) = mutex.lock() {
                if locked.0.is_none() {
                    // The wait queue entry is not associated with any [`WaitQueue`]
                    return Poll::Ready(());
                }

                locked.1.replace(cx.waker().clone());
            }
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

/// [`SyncWait`] is inserted into [`WaitQueue`] for the caller to synchronously wait
/// until signaled.
#[derive(Debug)]
struct SyncWait {
    next: AtomicUsize,
    condvar: Condvar,
    mutex: Mutex<bool>,
}

impl SyncWait {
    const fn new(next: usize) -> Self {
        Self {
            next: AtomicUsize::new(next),
            condvar: Condvar::new(),
            mutex: Mutex::new(false),
        }
    }

    fn wait(&self) {
        let mut completed = unsafe { self.mutex.lock().unwrap_unchecked() };
        while !*completed {
            completed = unsafe { self.condvar.wait(completed).unwrap_unchecked() };
        }
    }

    fn signal(&self) {
        let mut completed = unsafe { self.mutex.lock().unwrap_unchecked() };
        *completed = true;
        self.condvar.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn wait_queue_sync() {
        let num_tasks = 8;
        let barrier = Arc::new(Barrier::new(num_tasks + 1));
        let wait_queue = Arc::new(WaitQueue::default());
        let data = Arc::new(AtomicUsize::new(0));
        let mut task_handles = Vec::with_capacity(num_tasks);
        for task_id in 1..=num_tasks {
            let barrier_clone = barrier.clone();
            let wait_queue_clone = wait_queue.clone();
            let data_clone = data.clone();

            task_handles.push(thread::spawn(move || {
                barrier_clone.wait();
                while wait_queue_clone
                    .wait_sync(|| {
                        if data_clone
                            .compare_exchange(
                                task_id,
                                task_id + 1,
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                            )
                            .is_ok()
                        {
                            Ok(())
                        } else {
                            Err(())
                        }
                    })
                    .is_err()
                {
                    thread::yield_now();
                }
                wait_queue_clone.signal();
            }));
        }

        barrier.wait();
        data.fetch_add(1, Ordering::Release);
        wait_queue.signal();

        task_handles
            .into_iter()
            .for_each(|t| assert!(t.join().is_ok()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn wait_queue_async() {
        let num_tasks = 8;
        let barrier = Arc::new(tokio::sync::Barrier::new(num_tasks + 1));
        let wait_queue = Arc::new(WaitQueue::default());
        let data = Arc::new(AtomicUsize::new(0));
        let mut task_handles = Vec::with_capacity(num_tasks);
        for task_id in 1..=num_tasks {
            let barrier_clone = barrier.clone();
            let wait_queue_clone = wait_queue.clone();
            let data_clone = data.clone();

            task_handles.push(tokio::spawn(async move {
                barrier_clone.wait().await;
                let mut async_wait = AsyncWait::default();
                let mut async_wait_pinned = Pin::new(&mut async_wait);

                while wait_queue_clone
                    .push_async_entry(&mut async_wait_pinned, || {
                        if data_clone
                            .compare_exchange(
                                task_id,
                                task_id + 1,
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                            )
                            .is_ok()
                        {
                            Ok(())
                        } else {
                            Err(())
                        }
                    })
                    .is_err()
                {
                    async_wait_pinned.as_mut().await;
                    if data_clone.load(Ordering::Relaxed) > task_id {
                        break;
                    }
                    async_wait_pinned.mutex.take();
                }

                wait_queue_clone.signal();
            }));
        }

        barrier.wait().await;
        data.fetch_add(1, Ordering::Release);
        wait_queue.signal();

        for handle in futures::future::join_all(task_handles).await {
            assert!(handle.is_ok());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn wait_queue_async_drop() {
        let num_tasks = 8;
        let barrier = Arc::new(tokio::sync::Barrier::new(num_tasks));
        let wait_queue = Arc::new(WaitQueue::default());
        let mut task_handles = Vec::with_capacity(num_tasks);
        for task_id in 0..num_tasks {
            let barrier_clone = barrier.clone();
            let wait_queue_clone = wait_queue.clone();

            task_handles.push(tokio::spawn(async move {
                barrier_clone.wait().await;

                for _ in 0..num_tasks {
                    let mut async_wait = AsyncWait::default();
                    let mut async_wait_pinned = Pin::new(&mut async_wait);

                    if wait_queue_clone
                        .push_async_entry(&mut async_wait_pinned, || {
                            if task_id & 1 == 0 {
                                Ok(())
                            } else {
                                Err(())
                            }
                        })
                        .is_ok()
                    {
                        assert_eq!(task_id & 1, 0);
                    }
                }

                wait_queue_clone.signal();
            }));
        }

        for handle in futures::future::join_all(task_handles).await {
            assert!(handle.is_ok());
        }

        drop(wait_queue);
    }
}
