//! Outbound messages built inside the Signal service.
//!
//! The customer's app hands the service a `waE2E.Message`; wacore's stanza
//! builder pads it, adds own-device copies and encrypts it per device. The
//! WhatsApp client only answers device-list and prekey queries through the
//! [`SendContextResolver`] and transmits the finished stanza, so it never sees
//! the plaintext. Session changes and the sent-message record commit before
//! the stanza is returned, matching wacore's rule that Signal state is durable
//! before ciphertext is published.

use crate::error::OpsError;
use crate::ops::{ServiceStore, SignalOps};
use wacore::client::context::SendContextResolver;
use wacore::runtime::Runtime;
use wacore::send::{DmStanzaRequest, ResolvedDmDevices, SignalStores, prepare_dm_stanza};
use wacore_binary::{Jid, JidExt};
use wacore_recordstore::Namespace;
use waproto::whatsapp as wa;

/// A finished `<message>` stanza for the client to transmit.
#[derive(Debug, Clone)]
pub struct PreparedSend {
    /// The stanza, marshaled as the binary node format the socket writes.
    pub stanza: Vec<u8>,
    /// Devices that were addressed but got no `<enc>`.
    pub unreached_devices: Vec<Jid>,
    /// Device-list hash of the addressed set, for comparing with the server
    /// ack.
    pub phash: Option<String>,
}

fn sent_key(chat: &Jid, message_id: &str) -> String {
    format!("{chat}\u{0}{message_id}")
}

/// Sent-message record: `[has_secret][secret (32 bytes, when set)][message]`.
fn encode_sent(message: &[u8], secret: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + message.len());
    match secret {
        Some(secret) => {
            out.push(1);
            out.extend_from_slice(secret);
        }
        None => out.push(0),
    }
    out.extend_from_slice(message);
    out
}

fn send_error(error: anyhow::Error) -> OpsError {
    OpsError::Send(format!("{error:#}"))
}

impl<S: ServiceStore> SignalOps<S> {
    /// Build a direct-message stanza for `to`. Devices come from the
    /// resolver (the WhatsApp client); missing sessions are set up from
    /// bundles it fetches.
    pub async fn send_direct(
        &self,
        runtime: &dyn Runtime,
        resolver: &dyn SendContextResolver,
        to: &Jid,
        message: &wa::Message,
        message_id: &str,
    ) -> Result<PreparedSend, OpsError> {
        let keys = self.keys().await;
        let own_jid: Jid = keys
            .own_pn
            .as_deref()
            .ok_or_else(|| OpsError::InvalidInput("device is not paired: own JID unknown".into()))?
            .parse()
            .map_err(|_| OpsError::InvalidInput("stored own JID does not parse".into()))?;
        let own_lid: Option<Jid> = keys
            .own_lid
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| OpsError::InvalidInput("stored own LID does not parse".into()))?;
        let account = keys
            .account
            .as_deref()
            .map(waproto::codec::adv_signed_device_identity_decode)
            .transpose()
            .map_err(|_| {
                OpsError::InvalidInput("stored account identity does not decode".into())
            })?;

        let mut devices = resolver
            .resolve_devices(&[to.to_non_ad(), own_jid.to_non_ad()])
            .await
            .map_err(send_error)?;
        // Hosted (Cloud API) devices never get a copy, as in the client.
        devices.retain(|device| !device.is_hosted());
        wacore::types::jid::sort_dedup_by_device(&mut devices);
        let resolved = ResolvedDmDevices::new(devices, &own_jid, own_lid.as_ref());

        let lock = self.session_lock();
        let _guard = lock.lock().await;
        let staged = std::sync::Arc::new(self.store().staged());
        let stores = self.stores_over(staged.clone()).await;
        let (mut sender_keys, mut sessions, mut identities, mut prekeys, signed_prekeys) = (
            stores.clone(),
            stores.clone(),
            stores.clone(),
            stores.clone(),
            stores,
        );
        let mut signal = SignalStores {
            sender_key_store: &mut sender_keys,
            session_store: &mut sessions,
            identity_store: &mut identities,
            prekey_store: &mut prekeys,
            signed_prekey_store: &signed_prekeys,
        };
        let prepared = prepare_dm_stanza(
            runtime,
            &mut signal,
            resolver,
            DmStanzaRequest {
                own_jid: &own_jid,
                own_lid: own_lid.as_ref(),
                account: account.as_ref(),
                to,
                message,
                message_id,
                edit: None,
                extra_nodes: &[],
                devices: &resolved,
                pre_encoded: None,
            },
        )
        .await
        .map_err(send_error)?;

        let encoded = waproto::codec::message_to_vec(message);
        staged
            .put_aux(
                Namespace::SentMessage,
                &sent_key(to, message_id),
                &encode_sent(&encoded, prepared.message_secret.as_ref()),
            )
            .await?;
        staged.commit().await?;

        let stanza = wacore_binary::marshal(&prepared.node)
            .map_err(|e| OpsError::Send(format!("stanza did not marshal: {e}")))?;
        Ok(PreparedSend {
            stanza,
            unreached_devices: prepared.unreached_devices,
            phash: prepared.phash.map(|p| p.to_string()),
        })
    }

    /// The message this device sent to `chat` with `message_id`, if still
    /// kept. Used to answer retry receipts.
    pub async fn sent_message(
        &self,
        chat: &Jid,
        message_id: &str,
    ) -> Result<Option<wa::Message>, OpsError> {
        let Some(record) = self
            .store()
            .load_aux(Namespace::SentMessage, &sent_key(chat, message_id))
            .await?
        else {
            return Ok(None);
        };
        let body = match record.first() {
            Some(0) => &record[1..],
            Some(1) if record.len() >= 33 => &record[33..],
            _ => {
                return Err(OpsError::InvalidInput(
                    "sent-message record is corrupt".into(),
                ));
            }
        };
        waproto::codec::message_decode(body)
            .map(Some)
            .map_err(|e| OpsError::InvalidInput(format!("sent message did not decode: {e}")))
    }
}
