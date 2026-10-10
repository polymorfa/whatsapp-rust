//! Signal operations for a WhatsApp linked device whose private keys live
//! outside the WhatsApp client.
//!
//! The client (connection, receipts, retries, prekey upload, device lists)
//! runs elsewhere and calls these operations whenever it needs a private key:
//! decrypting and encrypting messages, sender keys, new prekeys, and the one
//! pairing signature. Everything here is pure Signal state over a
//! [`wacore::store::traits::SignalStore`]; nothing opens a socket.
//!
//! Message padding is the caller's concern: [`SignalOps::decrypt`] returns
//! libsignal's plaintext exactly as received and [`SignalOps::encrypt`] takes
//! already padded plaintext.

mod device;
mod error;
mod inbound;
mod ops;
mod outbound;
mod stores;

pub use device::{DeviceKeys, PublicIdentity, PublicPreKey, PublicSignedPreKey};
pub use error::OpsError;
pub use inbound::{ReceiveKind, ReceiveRequest, Received, ReceivedMessage};
pub use ops::{
    Decrypted, EncKind, Encrypted, PairingSignature, RemoteBundle, ServiceStore, SignalOps,
};
pub use outbound::PreparedSend;
