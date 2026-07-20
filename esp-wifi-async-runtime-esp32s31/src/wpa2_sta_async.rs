//! Async WPA2 STA M1-to-M2 transition with fixed owned storage.

use crate::{
    wpa2::OwnedEapolFrame,
    wpa2_crypto::Wpa2Ptk,
    wpa2_frames::{
        build_sta_action_frame, OwnedAssociationSecurityIes, Wpa2EthernetFrame, Wpa2FrameError,
        WPA2_TX_EAPOL_CAPACITY, WPA2_TX_ETHERNET_CAPACITY,
    },
    wpa2_state::{PtkContext, Wpa2StaAction, Wpa2StaState, Wpa2StateError},
};

/// Cryptography required before a STA can transmit WPA2 message 2.
///
/// Implementations own the scheduling boundary. A hardware implementation
/// should arm SHA work, return `Pending`, and resume from a completion IRQ. No
/// method may allocate, busy-poll, insert a delay, or wait on an RTOS object.
#[allow(async_fn_in_trait)]
pub trait AsyncWpa2StaCrypto {
    type Error;

    async fn derive_ptk(
        &mut self,
        pmk: &[u8; 32],
        context: PtkContext,
    ) -> Result<[u8; 48], Self::Error>;

    async fn hmac_sha1(
        &mut self,
        key: &[u8; 16],
        message_with_zeroed_mic: &[u8],
    ) -> Result<[u8; 20], Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum Wpa2StaMessage2Error<E> {
    State(Wpa2StateError),
    Frame(Wpa2FrameError),
    Crypto(E),
    UnexpectedAction,
}

pub struct Wpa2StaMessage2 {
    ptk: Wpa2Ptk,
    frame: Wpa2EthernetFrame<WPA2_TX_ETHERNET_CAPACITY>,
}

impl Wpa2StaMessage2 {
    pub const fn ptk(&self) -> &Wpa2Ptk {
        &self.ptk
    }

    pub const fn frame(&self) -> &Wpa2EthernetFrame<WPA2_TX_ETHERNET_CAPACITY> {
        &self.frame
    }

    pub fn into_parts(self) -> (Wpa2Ptk, Wpa2EthernetFrame<WPA2_TX_ETHERNET_CAPACITY>) {
        (self.ptk, self.frame)
    }
}

/// Consume one owned M1 and produce a complete Ethernet/EAPOL M2.
///
/// The state is advanced to `AwaitingMessage3` only after PTK derivation
/// succeeds. The returned frame owns all bytes and can be moved into a bounded
/// radio-owner command queue without retaining any borrowed packet pointer.
pub async fn derive_wpa2_sta_message2<C, const N: usize, const R: usize>(
    state: &mut Wpa2StaState,
    message1: OwnedEapolFrame<N>,
    pmk: &[u8; 32],
    security_ies: &OwnedAssociationSecurityIes<R>,
    crypto: &mut C,
) -> Result<Wpa2StaMessage2, Wpa2StaMessage2Error<C::Error>>
where
    C: AsyncWpa2StaCrypto,
{
    let (ticket, context) = match state
        .on_frame(message1)
        .map_err(Wpa2StaMessage2Error::State)?
    {
        Wpa2StaAction::DerivePtk { ticket, context } => (ticket, context),
        _ => return Err(Wpa2StaMessage2Error::UnexpectedAction),
    };

    let ptk = crypto
        .derive_ptk(pmk, context)
        .await
        .map(Wpa2Ptk::from_bytes)
        .map_err(Wpa2StaMessage2Error::Crypto)?;
    let transmit = match state
        .complete_ptk::<N>(ticket, true)
        .map_err(Wpa2StaMessage2Error::State)?
    {
        Wpa2StaAction::Transmit(transmit) => transmit,
        _ => return Err(Wpa2StaMessage2Error::UnexpectedAction),
    };

    let mut eapol =
        build_sta_action_frame::<WPA2_TX_EAPOL_CAPACITY, R>(state, transmit, security_ies)
            .map_err(Wpa2StaMessage2Error::Frame)?;
    let mic = crypto
        .hmac_sha1(ptk.kck(), eapol.as_bytes())
        .await
        .map_err(Wpa2StaMessage2Error::Crypto)?;
    eapol.set_mic(
        mic[..16]
            .try_into()
            .expect("a SHA-1 tag always contains a 16-byte WPA2 MIC"),
    );
    let frame = Wpa2EthernetFrame::build(*state.local_address(), &eapol)
        .map_err(Wpa2StaMessage2Error::Frame)?;
    Ok(Wpa2StaMessage2 { ptk, frame })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        wpa2::{EapolKeyMessage, Wpa2Interface},
        wpa2_frames::Wpa2TxFrame,
        wpa2_state::Wpa2StaPhase,
    };

    struct Crypto;

    impl AsyncWpa2StaCrypto for Crypto {
        type Error = ();

        async fn derive_ptk(
            &mut self,
            _pmk: &[u8; 32],
            _context: PtkContext,
        ) -> Result<[u8; 48], Self::Error> {
            Ok([0x55; 48])
        }

        async fn hmac_sha1(
            &mut self,
            _key: &[u8; 16],
            message: &[u8],
        ) -> Result<[u8; 20], Self::Error> {
            assert_eq!(&message[81..97], &[0; 16]);
            Ok([0xa5; 20])
        }
    }

    #[test]
    fn m1_becomes_owned_m2_after_async_crypto() {
        let local = [1; 6];
        let peer = [2; 6];
        let mut state = Wpa2StaState::new(local, peer, [3; 32]).unwrap();
        let source = Wpa2TxFrame::<128>::message1(peer, 7, [4; 32]).unwrap();
        let message1: OwnedEapolFrame<128> =
            OwnedEapolFrame::try_copy(Wpa2Interface::Station, peer, source.as_bytes()).unwrap();
        let mut rsn = [0; 22];
        rsn[0] = 0x30;
        rsn[1] = 20;
        let rsn: crate::wpa2_frames::OwnedRsnIe<22> =
            crate::wpa2_frames::OwnedRsnIe::try_copy(&rsn).unwrap();
        let security_ies = OwnedAssociationSecurityIes::<22>::try_copy(&rsn, &[]).unwrap();

        let mut crypto = Crypto;
        let output = futures_lite_for_test(derive_wpa2_sta_message2(
            &mut state,
            message1,
            &[9; 32],
            &security_ies,
            &mut crypto,
        ))
        .unwrap();

        assert_eq!(state.phase(), Wpa2StaPhase::AwaitingMessage3);
        assert_eq!(output.ptk().temporal_key(), &[0x55; 16]);
        assert_eq!(output.frame().interface(), Wpa2Interface::Station);
        let eapol = &output.frame().as_bytes()[14..];
        assert_eq!(
            crate::wpa2::EapolKeyFrame::parse(eapol).unwrap().message(),
            EapolKeyMessage::PairwiseMessage2
        );
        assert_eq!(&eapol[81..97], &[0xa5; 16]);
    }

    fn futures_lite_for_test<F: core::future::Future>(future: F) -> F::Output {
        use core::{
            pin::pin,
            task::{Context, Poll, Waker},
        };

        let mut future = pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test crypto unexpectedly returned Pending"),
        }
    }
}
