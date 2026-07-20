use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{compiler_fence, Ordering},
    task::{Context, Poll},
};

use crate::interrupt::InterruptSignal;

pub const AES_BLOCK_SIZE: usize = 16;
pub const WPA_PSK_PASSPHRASE_CAPACITY: usize = 63;
pub const WPA_SSID_CAPACITY: usize = 32;
pub const WPA_PMK_LENGTH: usize = 32;
pub const WPA_PBKDF2_ITERATIONS: u32 = 4096;

pub type WpaPskJob = CryptoJob<WPA_PSK_PASSPHRASE_CAPACITY, WPA_SSID_CAPACITY, WPA_PMK_LENGTH>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoOperation {
    Sha1,
    Sha256,
    HmacSha1,
    HmacSha256,
    Pbkdf2Sha1 {
        iterations: u32,
    },
    /// WPA2 SHA1 PRF-384 over the canonical 76-byte address/nonce context.
    Wpa2PtkSha1,
    Aes128CbcEncrypt,
    Aes128CbcDecrypt,
    /// RFC 3394 AES key wrap; output is eight bytes longer than input.
    Aes128KeyWrap,
    /// RFC 3394 AES key unwrap; output is eight bytes shorter than input.
    Aes128KeyUnwrap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoJobError {
    KeyTooLong,
    InputTooLong,
    OutputTooLong,
    InvalidKeyLength,
    InvalidIvLength,
    InvalidInputLength,
    InvalidOutputLength,
    NotComplete,
}

#[cfg(target_arch = "riscv32")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmkInstallError {
    JobNotComplete,
    NotRadioOwner,
}

/// Pinned, fixed-capacity storage retained for the complete lifetime of an
/// asynchronous crypto operation.
///
/// For PBKDF2, `key` contains the passphrase and `input` contains the SSID.
/// No pointer into this object may be retained after the crypto future returns.
pub struct CryptoJob<const KEY: usize, const INPUT: usize, const OUTPUT: usize> {
    operation: CryptoOperation,
    key: [u8; KEY],
    key_len: usize,
    iv: [u8; AES_BLOCK_SIZE],
    iv_len: usize,
    input: [u8; INPUT],
    input_len: usize,
    output: [u8; OUTPUT],
    output_len: usize,
    complete: bool,
}

impl<const KEY: usize, const INPUT: usize, const OUTPUT: usize> CryptoJob<KEY, INPUT, OUTPUT> {
    pub fn new(
        operation: CryptoOperation,
        key: &[u8],
        iv: &[u8],
        input: &[u8],
        output_len: usize,
    ) -> Result<Self, CryptoJobError> {
        if key.len() > KEY {
            return Err(CryptoJobError::KeyTooLong);
        }
        if input.len() > INPUT {
            return Err(CryptoJobError::InputTooLong);
        }
        if output_len > OUTPUT {
            return Err(CryptoJobError::OutputTooLong);
        }
        validate(operation, key.len(), iv.len(), input.len(), output_len)?;

        let mut job = Self {
            operation,
            key: [0; KEY],
            key_len: key.len(),
            iv: [0; AES_BLOCK_SIZE],
            iv_len: iv.len(),
            input: [0; INPUT],
            input_len: input.len(),
            output: [0; OUTPUT],
            output_len,
            complete: false,
        };
        job.key[..key.len()].copy_from_slice(key);
        job.iv[..iv.len()].copy_from_slice(iv);
        job.input[..input.len()].copy_from_slice(input);
        Ok(job)
    }

    pub const fn operation(&self) -> CryptoOperation {
        self.operation
    }

    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    pub fn iv(&self) -> &[u8] {
        &self.iv[..self.iv_len]
    }

    pub fn input(&self) -> &[u8] {
        &self.input[..self.input_len]
    }

    pub fn output_buffer(&mut self) -> &mut [u8] {
        &mut self.output[..self.output_len]
    }

    pub fn result(&self) -> Result<&[u8], CryptoJobError> {
        if self.complete {
            Ok(&self.output[..self.output_len])
        } else {
            Err(CryptoJobError::NotComplete)
        }
    }

    fn mark_started(&mut self) {
        self.complete = false;
    }

    fn mark_complete(&mut self) {
        self.complete = true;
    }
}

impl CryptoJob<WPA_PSK_PASSPHRASE_CAPACITY, WPA_SSID_CAPACITY, WPA_PMK_LENGTH> {
    /// Construct the expensive WPA/WPA2-Personal PMK derivation as an async
    /// job that can be completed before entering the synchronous blob.
    pub fn wpa_psk(passphrase: &[u8], ssid: &[u8]) -> Result<Self, CryptoJobError> {
        if !(8..=WPA_PSK_PASSPHRASE_CAPACITY).contains(&passphrase.len()) {
            return Err(CryptoJobError::InvalidKeyLength);
        }
        if ssid.is_empty() || ssid.len() > WPA_SSID_CAPACITY {
            return Err(CryptoJobError::InvalidInputLength);
        }
        Self::new(
            CryptoOperation::Pbkdf2Sha1 {
                iterations: WPA_PBKDF2_ITERATIONS,
            },
            passphrase,
            &[],
            ssid,
            WPA_PMK_LENGTH,
        )
    }
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    fn wpa_set_pmk(pmk: *mut u8, length: usize, pmkid: *const u8, external: bool);
}

/// Copy a completed async WPA-Personal PMK into the initialized supplicant.
///
/// The exported blob function copies the key synchronously and does not retain
/// a pointer into `job`. Calling this through [`crate::RadioOwnerFuture`]
/// prevents concurrent supplicant access and supplies virtual Wi-Fi identity.
///
/// # Safety
/// The supplicant must be initialized, its selected profile must expect the
/// same SSID/passphrase represented by `job`, and no later passphrase setup may
/// overwrite the installed PMK before connection.
#[cfg(target_arch = "riscv32")]
pub unsafe fn install_precomputed_wpa_pmk(job: &WpaPskJob) -> Result<(), PmkInstallError> {
    if !crate::context::in_radio_context() {
        return Err(PmkInstallError::NotRadioOwner);
    }
    let pmk = job.result().map_err(|_| PmkInstallError::JobNotComplete)?;
    wpa_set_pmk(pmk.as_ptr().cast_mut(), pmk.len(), core::ptr::null(), false);
    Ok(())
}

impl<const KEY: usize, const INPUT: usize, const OUTPUT: usize> Drop
    for CryptoJob<KEY, INPUT, OUTPUT>
{
    fn drop(&mut self) {
        // Volatile writes prevent secrets from being optimized back into the
        // stack after their owner is dropped.
        for byte in self
            .key
            .iter_mut()
            .chain(self.iv.iter_mut())
            .chain(self.input.iter_mut())
            .chain(self.output.iter_mut())
        {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

fn validate(
    operation: CryptoOperation,
    key_len: usize,
    iv_len: usize,
    input_len: usize,
    output_len: usize,
) -> Result<(), CryptoJobError> {
    match operation {
        CryptoOperation::Sha1 => {
            if key_len != 0 {
                return Err(CryptoJobError::InvalidKeyLength);
            }
            if iv_len != 0 {
                return Err(CryptoJobError::InvalidIvLength);
            }
            if output_len != 20 {
                return Err(CryptoJobError::InvalidOutputLength);
            }
        }
        CryptoOperation::Sha256 => {
            if key_len != 0 {
                return Err(CryptoJobError::InvalidKeyLength);
            }
            if iv_len != 0 {
                return Err(CryptoJobError::InvalidIvLength);
            }
            if output_len != 32 {
                return Err(CryptoJobError::InvalidOutputLength);
            }
        }
        CryptoOperation::HmacSha1 | CryptoOperation::HmacSha256 => {
            if key_len == 0 {
                return Err(CryptoJobError::InvalidKeyLength);
            }
            if iv_len != 0 {
                return Err(CryptoJobError::InvalidIvLength);
            }
            let expected = if operation == CryptoOperation::HmacSha1 {
                20
            } else {
                32
            };
            if output_len != expected {
                return Err(CryptoJobError::InvalidOutputLength);
            }
        }
        CryptoOperation::Pbkdf2Sha1 { iterations } => {
            if key_len == 0 || iterations == 0 {
                return Err(CryptoJobError::InvalidKeyLength);
            }
            if iv_len != 0 {
                return Err(CryptoJobError::InvalidIvLength);
            }
            if input_len == 0 {
                return Err(CryptoJobError::InvalidInputLength);
            }
            if output_len == 0 {
                return Err(CryptoJobError::InvalidOutputLength);
            }
        }
        CryptoOperation::Wpa2PtkSha1 => {
            if key_len != WPA_PMK_LENGTH {
                return Err(CryptoJobError::InvalidKeyLength);
            }
            if iv_len != 0 {
                return Err(CryptoJobError::InvalidIvLength);
            }
            if input_len != 76 {
                return Err(CryptoJobError::InvalidInputLength);
            }
            if output_len != 48 {
                return Err(CryptoJobError::InvalidOutputLength);
            }
        }
        CryptoOperation::Aes128CbcEncrypt | CryptoOperation::Aes128CbcDecrypt => {
            if key_len != AES_BLOCK_SIZE {
                return Err(CryptoJobError::InvalidKeyLength);
            }
            if iv_len != AES_BLOCK_SIZE {
                return Err(CryptoJobError::InvalidIvLength);
            }
            if input_len == 0 || !input_len.is_multiple_of(AES_BLOCK_SIZE) {
                return Err(CryptoJobError::InvalidInputLength);
            }
            if output_len != input_len {
                return Err(CryptoJobError::InvalidOutputLength);
            }
        }
        CryptoOperation::Aes128KeyWrap => {
            if key_len != AES_BLOCK_SIZE {
                return Err(CryptoJobError::InvalidKeyLength);
            }
            if iv_len != 0 {
                return Err(CryptoJobError::InvalidIvLength);
            }
            if input_len < 16 || !input_len.is_multiple_of(8) {
                return Err(CryptoJobError::InvalidInputLength);
            }
            if output_len != input_len + 8 {
                return Err(CryptoJobError::InvalidOutputLength);
            }
        }
        CryptoOperation::Aes128KeyUnwrap => {
            if key_len != AES_BLOCK_SIZE {
                return Err(CryptoJobError::InvalidKeyLength);
            }
            if iv_len != 0 {
                return Err(CryptoJobError::InvalidIvLength);
            }
            if input_len < 16 || !input_len.is_multiple_of(8) {
                return Err(CryptoJobError::InvalidInputLength);
            }
            if output_len != input_len - 8 {
                return Err(CryptoJobError::InvalidOutputLength);
            }
        }
    }
    Ok(())
}

/// Hardware-specific half of the async crypto boundary.
///
/// `start` may retain pointers into the pinned job until `finish` or `abort`.
/// It must return immediately after arming the peripheral. The completion ISR
/// only signals [`InterruptSignal`].
pub trait InterruptCryptoBackend<const KEY: usize, const INPUT: usize, const OUTPUT: usize> {
    type Error;

    fn start(&mut self, job: Pin<&mut CryptoJob<KEY, INPUT, OUTPUT>>) -> Result<(), Self::Error>;

    fn is_complete(&mut self) -> Result<bool, Self::Error>;

    fn finish(&mut self, job: Pin<&mut CryptoJob<KEY, INPUT, OUTPUT>>) -> Result<(), Self::Error>;

    fn abort(&mut self, job: Pin<&mut CryptoJob<KEY, INPUT, OUTPUT>>);
}

pub struct InterruptCryptoEngine<'a, B> {
    backend: B,
    completion: &'a InterruptSignal,
}

impl<'a, B> InterruptCryptoEngine<'a, B> {
    pub const fn new(backend: B, completion: &'a InterruptSignal) -> Self {
        Self {
            backend,
            completion,
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn run<'engine, 'job, const KEY: usize, const INPUT: usize, const OUTPUT: usize>(
        &'engine mut self,
        job: Pin<&'job mut CryptoJob<KEY, INPUT, OUTPUT>>,
    ) -> CryptoFuture<'engine, 'job, 'a, B, KEY, INPUT, OUTPUT>
    where
        B: InterruptCryptoBackend<KEY, INPUT, OUTPUT>,
    {
        CryptoFuture {
            engine: self,
            job,
            observed_generation: 0,
            started: false,
            finished: false,
        }
    }
}

pub struct CryptoFuture<
    'engine,
    'job,
    'signal,
    B,
    const KEY: usize,
    const INPUT: usize,
    const OUTPUT: usize,
> where
    B: InterruptCryptoBackend<KEY, INPUT, OUTPUT>,
{
    engine: &'engine mut InterruptCryptoEngine<'signal, B>,
    job: Pin<&'job mut CryptoJob<KEY, INPUT, OUTPUT>>,
    observed_generation: usize,
    started: bool,
    finished: bool,
}

impl<B, const KEY: usize, const INPUT: usize, const OUTPUT: usize> Future
    for CryptoFuture<'_, '_, '_, B, KEY, INPUT, OUTPUT>
where
    B: InterruptCryptoBackend<KEY, INPUT, OUTPUT>,
{
    type Output = Result<(), B::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if !this.started {
            this.observed_generation = this.engine.completion.generation();
            this.job.as_mut().get_mut().mark_started();
            if let Err(error) = this.engine.backend.start(this.job.as_mut()) {
                this.finished = true;
                return Poll::Ready(Err(error));
            }
            this.started = true;
        }

        // Read hardware status only after a completion interrupt changes the
        // generation. Unrelated executor polls never poll the peripheral.
        let mut interrupt = this.engine.completion.wait_after(this.observed_generation);
        if let Poll::Ready(generation) = Pin::new(&mut interrupt).poll(cx) {
            this.observed_generation = generation;
            match this.engine.backend.is_complete() {
                Ok(true) => {
                    let result = this.engine.backend.finish(this.job.as_mut());
                    if result.is_ok() {
                        this.job.as_mut().get_mut().mark_complete();
                    }
                    this.finished = true;
                    return Poll::Ready(result);
                }
                Ok(false) => {}
                Err(error) => {
                    this.engine.backend.abort(this.job.as_mut());
                    this.finished = true;
                    return Poll::Ready(Err(error));
                }
            }
        }
        Poll::Pending
    }
}

impl<B, const KEY: usize, const INPUT: usize, const OUTPUT: usize> Drop
    for CryptoFuture<'_, '_, '_, B, KEY, INPUT, OUTPUT>
where
    B: InterruptCryptoBackend<KEY, INPUT, OUTPUT>,
{
    fn drop(&mut self) {
        if self.started && !self.finished {
            self.engine.backend.abort(self.job.as_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use core::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::{Context, Poll, Waker},
    };

    use super::{CryptoJob, CryptoOperation, InterruptCryptoBackend, InterruptCryptoEngine};
    use crate::interrupt::InterruptSignal;

    struct Backend<'a> {
        complete: &'a AtomicBool,
        aborted: &'a AtomicBool,
        status_reads: &'a AtomicUsize,
    }

    impl InterruptCryptoBackend<0, 8, 20> for Backend<'_> {
        type Error = ();

        fn start(&mut self, _job: Pin<&mut CryptoJob<0, 8, 20>>) -> Result<(), Self::Error> {
            Ok(())
        }

        fn is_complete(&mut self) -> Result<bool, Self::Error> {
            self.status_reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.complete.load(Ordering::Acquire))
        }

        fn finish(&mut self, mut job: Pin<&mut CryptoJob<0, 8, 20>>) -> Result<(), Self::Error> {
            job.output_buffer().fill(0x5a);
            Ok(())
        }

        fn abort(&mut self, _job: Pin<&mut CryptoJob<0, 8, 20>>) {
            self.aborted.store(true, Ordering::Release);
        }
    }

    #[test]
    fn crypto_job_completes_only_after_interrupt() {
        let signal = InterruptSignal::new();
        let complete = AtomicBool::new(false);
        let aborted = AtomicBool::new(false);
        let status_reads = AtomicUsize::new(0);
        let backend = Backend {
            complete: &complete,
            aborted: &aborted,
            status_reads: &status_reads,
        };
        let mut engine = InterruptCryptoEngine::new(backend, &signal);
        let mut job =
            CryptoJob::<0, 8, 20>::new(CryptoOperation::Sha1, &[], &[], b"payload", 20).unwrap();
        let mut future = engine.run(Pin::new(&mut job));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        assert_eq!(Pin::new(&mut future).poll(&mut context), Poll::Pending);
        assert_eq!(status_reads.load(Ordering::Relaxed), 0);
        complete.store(true, Ordering::Release);
        signal.notify_from_isr();
        assert_eq!(
            Pin::new(&mut future).poll(&mut context),
            Poll::Ready(Ok(()))
        );
        assert_eq!(status_reads.load(Ordering::Relaxed), 1);
        drop(future);
        assert_eq!(job.result().unwrap(), &[0x5a; 20]);
        assert!(!aborted.load(Ordering::Acquire));
    }

    #[test]
    fn dropping_an_active_crypto_future_aborts_hardware() {
        let signal = InterruptSignal::new();
        let complete = AtomicBool::new(false);
        let aborted = AtomicBool::new(false);
        let status_reads = AtomicUsize::new(0);
        let backend = Backend {
            complete: &complete,
            aborted: &aborted,
            status_reads: &status_reads,
        };
        let mut engine = InterruptCryptoEngine::new(backend, &signal);
        let mut job =
            CryptoJob::<0, 8, 20>::new(CryptoOperation::Sha1, &[], &[], b"payload", 20).unwrap();
        let mut future = engine.run(Pin::new(&mut job));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert_eq!(Pin::new(&mut future).poll(&mut context), Poll::Pending);
        drop(future);
        assert!(aborted.load(Ordering::Acquire));
    }

    #[test]
    fn wpa_psk_job_owns_passphrase_and_ssid() {
        let passphrase = *b"correct horse battery staple";
        let mut ssid = *b"network";
        let job = super::WpaPskJob::wpa_psk(&passphrase, &ssid).unwrap();
        ssid.fill(0);
        assert_eq!(job.key(), &passphrase);
        assert_eq!(job.input(), b"network");
        assert_eq!(
            job.operation(),
            CryptoOperation::Pbkdf2Sha1 { iterations: 4096 }
        );
    }
}
