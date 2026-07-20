use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{event::PpEvent, queue::RadioQueue};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchControl {
    Continue,
    Stop,
}

/// Run-to-completion PP event dispatcher.
///
/// Implementations must not wait for queues, semaphores, timers, or task
/// notifications. Returning from this method is the only scheduling boundary.
pub trait PpDispatcher {
    type Error;

    fn dispatch(&mut self, event: PpEvent) -> Result<DispatchControl, Self::Error>;
}

/// Wake-driven replacement for the vendor `ppTask` loop.
pub struct RadioFuture<'a, D, const N: usize> {
    queue: &'a RadioQueue<N>,
    dispatcher: D,
    event_budget: usize,
    stop_requested: bool,
}

impl<'a, D, const N: usize> RadioFuture<'a, D, N> {
    pub fn new(queue: &'a RadioQueue<N>, dispatcher: D, event_budget: usize) -> Self {
        assert!(event_budget > 0);
        Self {
            queue,
            dispatcher,
            event_budget,
            stop_requested: false,
        }
    }

    pub fn dispatcher(&self) -> &D {
        &self.dispatcher
    }

    pub fn dispatcher_mut(&mut self) -> &mut D {
        &mut self.dispatcher
    }
}

impl<D: PpDispatcher + Unpin, const N: usize> Future for RadioFuture<'_, D, N> {
    type Output = Result<(), D::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Register before inspecting the queue. A producer racing this poll
        // either observes the waker or leaves a pending wake for registration.
        self.queue.register_waker(cx.waker());

        for _ in 0..self.event_budget {
            let Some(event) = self.queue.try_pop() else {
                return if self.stop_requested {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                };
            };

            match self.dispatcher.dispatch(event) {
                Ok(DispatchControl::Continue) => {}
                // The vendor loop drains messages already queued after event
                // 15 before deleting its task. Preserve that ownership rule.
                Ok(DispatchControl::Stop) => self.stop_requested = true,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }

        // Preserve fairness if producers keep the radio queue continuously
        // non-empty. This schedules one additional executor poll, not a busy
        // loop or a stack/context switch.
        if self.stop_requested || !self.queue.is_empty() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use core::{
        ffi::c_void,
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    use super::{DispatchControl, PpDispatcher, RadioFuture};
    use crate::{event::PpEvent, queue::RadioQueue};

    #[derive(Default)]
    struct Dispatcher {
        calls: usize,
    }

    impl PpDispatcher for Dispatcher {
        type Error = ();

        fn dispatch(&mut self, event: PpEvent) -> Result<DispatchControl, Self::Error> {
            self.calls += 1;
            Ok(if event.kind == 15 {
                DispatchControl::Stop
            } else {
                DispatchControl::Continue
            })
        }
    }

    fn event(kind: u32) -> PpEvent {
        PpEvent {
            kind,
            argument: core::ptr::null_mut::<c_void>(),
        }
    }

    #[test]
    fn future_only_dispatches_ready_events() {
        let queue = RadioQueue::<4>::new();
        let mut future = RadioFuture::new(&queue, Dispatcher::default(), 4);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        assert_eq!(Pin::new(&mut future).poll(&mut context), Poll::Pending);
        queue.try_push(event(8)).unwrap();
        assert_eq!(Pin::new(&mut future).poll(&mut context), Poll::Pending);
        assert_eq!(future.dispatcher().calls, 1);

        queue.try_push(event(15)).unwrap();
        assert_eq!(
            Pin::new(&mut future).poll(&mut context),
            Poll::Ready(Ok(()))
        );
        assert_eq!(future.dispatcher().calls, 2);
    }
}
