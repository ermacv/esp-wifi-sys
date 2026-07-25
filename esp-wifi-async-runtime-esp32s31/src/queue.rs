use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::Waker,
};

use crate::event::PpEvent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PushError(pub PpEvent);

struct Slot {
    sequence: AtomicUsize,
    event: UnsafeCell<MaybeUninit<PpEvent>>,
}

impl Slot {
    const fn new(sequence: usize) -> Self {
        Self {
            sequence: AtomicUsize::new(sequence),
            event: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

// Access to the event cell is owned by the sequence-number protocol.
unsafe impl Sync for Slot {}

/// Fixed-capacity multi-producer queue suitable for task and ISR producers and
/// one async radio consumer.
///
/// Enqueue/dequeue make one atomic claim attempt. They never allocate or retry;
/// capacity exhaustion and producer contention are both returned immediately
/// so the OSI adapter can apply event-specific overflow policy.
pub struct RadioQueue<const N: usize> {
    enqueue: AtomicUsize,
    dequeue: AtomicUsize,
    pushed: AtomicUsize,
    popped: AtomicUsize,
    rejected: AtomicUsize,
    high_water: AtomicUsize,
    slots: [Slot; N],
    waker: WakerCell,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RadioQueueSnapshot {
    pub pushed: usize,
    pub popped: usize,
    pub rejected: usize,
    pub queued: usize,
    pub high_water: usize,
    pub capacity: usize,
}

#[inline(always)]
fn record_high_water(counter: &AtomicUsize, value: usize) {
    let observed = counter.load(Ordering::Relaxed);
    if value > observed {
        // Queue producers are wait-free. A diagnostic update gets one CAS
        // attempt and never turns contention into a retry loop.
        let _ = counter.compare_exchange(observed, value, Ordering::Relaxed, Ordering::Relaxed);
    }
}

impl<const N: usize> RadioQueue<N> {
    pub const fn new() -> Self {
        assert!(N > 0);

        let mut slots = [const { Slot::new(0) }; N];
        let mut index = 0;
        while index < N {
            slots[index] = Slot::new(index);
            index += 1;
        }

        Self {
            enqueue: AtomicUsize::new(0),
            dequeue: AtomicUsize::new(0),
            pushed: AtomicUsize::new(0),
            popped: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            slots,
            waker: WakerCell::new(),
        }
    }

    pub fn try_push(&self, event: PpEvent) -> Result<(), PushError> {
        self.try_push_deferred_wake(event)?;
        self.wake_consumer();
        Ok(())
    }

    /// Claim and publish one event without waking the consumer yet.
    ///
    /// This split form lets the strict `pp_post` adapter keep its local
    /// interrupt exclusion through both the vendor signal-counter update and
    /// queue publication, then invoke the executor waker after interrupts are
    /// restored. It is still one fixed-cost claim attempt and never retries.
    #[inline(always)]
    pub(crate) fn try_push_deferred_wake(&self, event: PpEvent) -> Result<(), PushError> {
        if N == 1 {
            let slot = &self.slots[0];
            if slot
                .sequence
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                return Err(PushError(event));
            }
            unsafe { (*slot.event.get()).write(event) };
            self.enqueue.fetch_add(1, Ordering::Release);
            slot.sequence.store(2, Ordering::Release);
            self.pushed.fetch_add(1, Ordering::Relaxed);
            record_high_water(&self.high_water, 1);
            return Ok(());
        }

        let position = self.enqueue.load(Ordering::Relaxed);
        let slot = &self.slots[position % N];
        let sequence = slot.sequence.load(Ordering::Acquire);
        if sequence.wrapping_sub(position) as isize != 0
            || self
                .enqueue
                .compare_exchange(
                    position,
                    position.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(PushError(event));
        }

        unsafe { (*slot.event.get()).write(event) };
        slot.sequence
            .store(position.wrapping_add(1), Ordering::Release);
        self.pushed.fetch_add(1, Ordering::Relaxed);
        record_high_water(&self.high_water, self.len());
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn wake_consumer(&self) {
        self.waker.wake();
    }

    pub fn try_pop(&self) -> Option<PpEvent> {
        if N == 1 {
            let slot = &self.slots[0];
            if slot.sequence.load(Ordering::Acquire) != 2 {
                return None;
            }
            slot.sequence.store(3, Ordering::Relaxed);
            let event = unsafe { (*slot.event.get()).assume_init_read() };
            self.dequeue.fetch_add(1, Ordering::Release);
            slot.sequence.store(0, Ordering::Release);
            self.popped.fetch_add(1, Ordering::Relaxed);
            return Some(event);
        }

        let position = self.dequeue.load(Ordering::Relaxed);
        let slot = &self.slots[position % N];
        let expected = position.wrapping_add(1);
        let sequence = slot.sequence.load(Ordering::Acquire);
        if sequence.wrapping_sub(expected) as isize != 0 {
            return None;
        }

        self.dequeue
            .store(position.wrapping_add(1), Ordering::Relaxed);
        let event = unsafe { (*slot.event.get()).assume_init_read() };
        slot.sequence
            .store(position.wrapping_add(N), Ordering::Release);
        self.popped.fetch_add(1, Ordering::Relaxed);
        Some(event)
    }

    pub fn register_waker(&self, waker: &Waker) {
        self.waker.register(waker);
    }

    pub fn is_empty(&self) -> bool {
        self.dequeue.load(Ordering::Acquire) == self.enqueue.load(Ordering::Acquire)
    }

    /// Snapshot of messages claimed by producers and not yet claimed by the
    /// consumer. A producer may still be publishing the newest item.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.enqueue
            .load(Ordering::Acquire)
            .wrapping_sub(self.dequeue.load(Ordering::Acquire))
    }

    pub fn snapshot(&self) -> RadioQueueSnapshot {
        RadioQueueSnapshot {
            pushed: self.pushed.load(Ordering::Acquire),
            popped: self.popped.load(Ordering::Acquire),
            rejected: self.rejected.load(Ordering::Acquire),
            queued: self.len(),
            high_water: self.high_water.load(Ordering::Acquire),
            capacity: N,
        }
    }
}

impl<const N: usize> Default for RadioQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct WakerCell {
    locked: AtomicBool,
    pending: AtomicBool,
    waker: UnsafeCell<Option<Waker>>,
}

impl WakerCell {
    pub(crate) const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            pending: AtomicBool::new(false),
            waker: UnsafeCell::new(None),
        }
    }

    pub(crate) fn register(&self, waker: &Waker) {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.pending.store(true, Ordering::Release);
            // Registration raced the short interrupt-side wake critical
            // section. Reschedule once instead of spinning in this poll.
            waker.wake_by_ref();
            return;
        }

        let registered = unsafe { &mut *self.waker.get() };
        if registered
            .as_ref()
            .is_none_or(|registered| !registered.will_wake(waker))
        {
            *registered = Some(waker.clone());
        }
        self.locked.store(false, Ordering::Release);

        // A producer that ran while registration held the lock leaves this
        // flag set instead of spinning in an interrupt context.
        if self.pending.swap(false, Ordering::AcqRel) {
            waker.wake_by_ref();
        }
    }

    #[inline(always)]
    pub(crate) fn wake(&self) {
        self.pending.store(true, Ordering::Release);

        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let registered = unsafe { &mut *self.waker.get() };
        // Move the waker out instead of cloning from an interrupt context.
        // The next executor poll registers it again.
        let to_wake = registered.take();
        if to_wake.is_some() {
            self.pending.store(false, Ordering::Release);
        }
        self.locked.store(false, Ordering::Release);

        if let Some(waker) = to_wake {
            waker.wake();
        }
    }
}

unsafe impl Sync for WakerCell {}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::RadioQueue;
    use crate::event::PpEvent;

    fn event(kind: u32) -> PpEvent {
        PpEvent {
            kind,
            argument: ptr::null_mut(),
        }
    }

    #[test]
    fn queue_reports_full_and_preserves_order() {
        let queue = RadioQueue::<2>::new();
        assert_eq!(queue.try_push(event(1)), Ok(()));
        assert_eq!(queue.try_push(event(2)), Ok(()));
        assert_eq!(queue.try_push(event(3)).unwrap_err().0.kind, 3);
        assert_eq!(queue.try_pop().unwrap().kind, 1);
        assert_eq!(queue.try_pop().unwrap().kind, 2);
        assert!(queue.try_pop().is_none());
        assert_eq!(
            queue.snapshot(),
            super::RadioQueueSnapshot {
                pushed: 2,
                popped: 2,
                rejected: 1,
                queued: 0,
                high_water: 2,
                capacity: 2,
            }
        );
    }

    #[test]
    fn one_slot_queue_reports_full_without_retrying() {
        let queue = RadioQueue::<1>::new();
        queue.try_push(event(1)).unwrap();
        assert_eq!(queue.try_push(event(2)).unwrap_err().0.kind, 2);
        assert_eq!(queue.try_pop().unwrap().kind, 1);
        queue.try_push(event(3)).unwrap();
        assert_eq!(queue.try_pop().unwrap().kind, 3);
    }

    #[test]
    fn slots_can_be_reused_after_wrap() {
        let queue = RadioQueue::<3>::new();
        for kind in 0..100 {
            queue.try_push(event(kind)).unwrap();
            assert_eq!(queue.try_pop().unwrap().kind, kind);
        }
    }
}
