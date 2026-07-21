use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};

use crate::{
    channel::{BoundedChannel, Receive, TrySendError},
    context::RadioContextGuard,
    queue::WakerCell,
};

/// Synthetic event identity used while the single radio owner handles an
/// application command.
pub const RADIO_COMMAND_CONTEXT_EVENT: u32 = u32::MAX - 32;

/// Fixed-capacity ownership channel for application-to-radio commands.
///
/// Producers never call the vendor API and never wait for the radio owner.
/// Queue saturation is explicit and leaves ownership with the producer.
pub struct RadioCommandQueue<C, const N: usize> {
    channel: BoundedChannel<C, N>,
    rejected: AtomicUsize,
    capacity_waker: WakerCell,
}

impl<C, const N: usize> RadioCommandQueue<C, N> {
    pub const fn new() -> Self {
        Self {
            channel: BoundedChannel::new(),
            rejected: AtomicUsize::new(0),
            capacity_waker: WakerCell::new(),
        }
    }

    pub fn try_submit(&self, command: C) -> Result<(), TrySendError<C>> {
        self.channel.try_send(command).inspect_err(|_| {
            self.rejected.fetch_add(1, Ordering::Relaxed);
        })
    }

    pub fn try_receive(&self) -> Option<C> {
        self.channel
            .try_receive()
            .inspect(|_| self.capacity_waker.wake())
    }

    pub fn receive(&self) -> Receive<'_, C, N> {
        self.channel.receive()
    }

    pub fn rejected(&self) -> usize {
        self.rejected.load(Ordering::Acquire)
    }

    pub fn len(&self) -> usize {
        self.channel.len()
    }

    pub fn is_empty(&self) -> bool {
        self.channel.is_empty()
    }

    /// Wait asynchronously until a bounded command slot may be available.
    ///
    /// A producer still has to use [`try_submit`](Self::try_submit) after this
    /// returns because another producer can win the slot. The future never
    /// spins or sleeps; command consumption wakes it.
    pub fn ready(&self) -> RadioCommandReady<'_, C, N> {
        RadioCommandReady { queue: self }
    }

    /// Submit with Rust-async backpressure while retaining command ownership.
    pub async fn submit(&self, mut command: C) {
        loop {
            match self.try_submit(command) {
                Ok(()) => return,
                Err(error) => command = error.0,
            }
            self.ready().await;
        }
    }
}

impl<C, const N: usize> Default for RadioCommandQueue<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RadioCommandReady<'a, C, const N: usize> {
    queue: &'a RadioCommandQueue<C, N>,
}

impl<C, const N: usize> Future for RadioCommandReady<'_, C, N> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.queue.capacity_waker.register(cx.waker());
        if self.queue.len() < N {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Run-to-completion handler owned exclusively by [`RadioOwnerFuture`].
pub trait RadioCommandHandler<C> {
    type Error;

    fn handle(&mut self, command: C) -> Result<(), Self::Error>;
}

/// Polls application commands and the Wi-Fi runtime on the same executor
/// stack. This is the only application-facing location that enters logical
/// Wi-Fi task identity.
pub struct RadioOwnerFuture<'a, W, C, H, const N: usize> {
    wifi: W,
    commands: &'a RadioCommandQueue<C, N>,
    handler: H,
    command_budget: usize,
}

impl<'a, W, C, H, const N: usize> RadioOwnerFuture<'a, W, C, H, N> {
    pub fn new(
        wifi: W,
        commands: &'a RadioCommandQueue<C, N>,
        handler: H,
        command_budget: usize,
    ) -> Self {
        assert!(command_budget > 0);
        Self {
            wifi,
            commands,
            handler,
            command_budget,
        }
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }

    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    pub fn wifi(&self) -> &W {
        &self.wifi
    }
}

impl<W, C, H, const N: usize> Future for RadioOwnerFuture<'_, W, C, H, N>
where
    W: Future + Unpin,
    H: RadioCommandHandler<C> + Unpin,
{
    type Output = Result<W::Output, H::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut received = 0;
        let mut receive = self.commands.receive();

        while received < self.command_budget {
            let command = if received == 0 {
                match Pin::new(&mut receive).poll(cx) {
                    Poll::Ready(command) => {
                        self.commands.capacity_waker.wake();
                        command
                    }
                    Poll::Pending => break,
                }
            } else {
                match self.commands.try_receive() {
                    Some(command) => command,
                    None => break,
                }
            };

            let result = {
                let _radio_context = RadioContextGuard::enter(RADIO_COMMAND_CONTEXT_EVENT);
                self.handler.handle(command)
            };
            if let Err(error) = result {
                return Poll::Ready(Err(error));
            }
            received += 1;
        }

        if received == self.command_budget && !self.commands.is_empty() {
            cx.waker().wake_by_ref();
        }

        match Pin::new(&mut self.wifi).poll(cx) {
            Poll::Ready(output) => Poll::Ready(Ok(output)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::{
        future::{pending, Future},
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    use super::{RadioCommandHandler, RadioCommandQueue, RadioOwnerFuture};
    use crate::context::in_radio_context;

    #[derive(Default)]
    struct Handler {
        sum: u32,
        all_in_radio_context: bool,
    }

    impl RadioCommandHandler<u32> for Handler {
        type Error = ();

        fn handle(&mut self, command: u32) -> Result<(), Self::Error> {
            self.sum += command;
            self.all_in_radio_context = in_radio_context();
            Ok(())
        }
    }

    #[test]
    fn commands_only_run_under_the_radio_owner() {
        let commands = RadioCommandQueue::<u32, 2>::new();
        commands.try_submit(2).unwrap();
        commands.try_submit(3).unwrap();
        let mut owner = RadioOwnerFuture::new(pending::<()>(), &commands, Handler::default(), 2);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        assert_eq!(Pin::new(&mut owner).poll(&mut context), Poll::Pending);
        assert_eq!(owner.handler().sum, 5);
        assert!(owner.handler().all_in_radio_context);
        assert!(!in_radio_context());
    }

    #[test]
    fn async_submit_retains_command_until_capacity_is_woken() {
        let commands = RadioCommandQueue::<u32, 1>::new();
        commands.try_submit(7).unwrap();
        let mut submit = core::pin::pin!(commands.submit(9));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        assert_eq!(submit.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(commands.try_receive(), Some(7));
        assert_eq!(submit.as_mut().poll(&mut context), Poll::Ready(()));
        assert_eq!(commands.try_receive(), Some(9));
    }
}
