use wacore::libsignal::protocol::SignalProtocolError;
use wacore::store::error::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum OpsError {
    #[error("signal protocol error")]
    Signal(#[from] SignalProtocolError),
    #[error("store error")]
    Store(#[from] StoreError),
    /// The caller sent something this operation cannot accept.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Pairing was refused. `code` and `text` are the values WhatsApp Web
    /// answers the server with for the same failure.
    #[error("pairing refused: {code} {text}")]
    Pairing { code: u16, text: &'static str },
    /// Building an outbound stanza failed, including resolver (device list,
    /// prekey fetch) failures reported by the WhatsApp client.
    #[error("send failed: {0}")]
    Send(String),
    /// The scope has no device keys yet; call `SignalOps::create`.
    #[error("device keys are not initialised for this scope")]
    NotInitialised,
}

impl OpsError {
    /// The store refused a write because another node now holds the scope.
    /// The caller must stop serving it.
    pub fn is_fence_lost(&self) -> bool {
        match self {
            OpsError::Store(e) => wacore_recordstore::is_fence_lost(e),
            OpsError::Signal(SignalProtocolError::BackendError(_, source)) => source
                .downcast_ref::<StoreError>()
                .is_some_and(wacore_recordstore::is_fence_lost),
            _ => false,
        }
    }
}
