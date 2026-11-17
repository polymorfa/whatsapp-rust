use wacore::libsignal::protocol::SignalProtocolError;
use wacore::store::error::StoreError;

#[derive(Debug, thiserror::Error)]
#[error("a Signal operation was interrupted; acquire a new fenced instance")]
struct InterruptedOperation;

pub(crate) fn interrupted_operation() -> OpsError {
    StoreError::Database(Box::new(InterruptedOperation)).into()
}

fn state_is_refused(error: &StoreError) -> bool {
    wacore_recordstore::is_fence_lost(error)
        || matches!(error, StoreError::Database(source) if source.is::<InterruptedOperation>())
}

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
    /// The state must no longer be served: its lease moved, or cancellation
    /// left a write with uncertain completion. Release the lease and open a
    /// new instance at a higher fence before resuming operations.
    pub fn is_fence_lost(&self) -> bool {
        match self {
            OpsError::Store(e) => state_is_refused(e),
            OpsError::Signal(error) => signal_state_is_refused(error),
            _ => false,
        }
    }
}

fn signal_state_is_refused(error: &SignalProtocolError) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if current
            .downcast_ref::<StoreError>()
            .is_some_and(state_is_refused)
        {
            return true;
        }
        source = current.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapped_backend(source: StoreError, depth: usize) -> OpsError {
        let mut error = SignalProtocolError::BackendError("authored store", Box::new(source));
        for _ in 0..depth {
            error = SignalProtocolError::PreKeyBundleFinalizationFailed(Box::new(error));
        }
        OpsError::Signal(error)
    }

    #[test]
    fn finalization_preserves_lost_fence_and_interrupted_state() {
        for depth in [0, 1, 3] {
            let lost = wacore_recordstore::FenceLost {
                scope: "authored-fence-classification".into(),
                generation: 7,
            }
            .into_store_error();
            assert!(
                wrapped_backend(lost, depth).is_fence_lost(),
                "lost fence at depth {depth}"
            );
            let OpsError::Store(interrupted) = interrupted_operation() else {
                unreachable!()
            };
            assert!(
                wrapped_backend(interrupted, depth).is_fence_lost(),
                "interrupted state at depth {depth}"
            );
        }
    }

    #[test]
    fn finalization_keeps_ordinary_failures_distinct_from_state_refusal() {
        for depth in [0, 1, 3] {
            let io = StoreError::Io(std::io::Error::other("authored ordinary I/O error"));
            assert!(!wrapped_backend(io, depth).is_fence_lost());
        }
        assert!(
            !OpsError::Signal(SignalProtocolError::PreKeyBundleFinalizationFailed(
                Box::new(SignalProtocolError::InvalidArgument(
                    "authored input failure".into()
                ),)
            ))
            .is_fence_lost()
        );
    }
}
