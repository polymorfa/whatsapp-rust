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
use std::collections::HashSet;
use wacore::client::context::SendContextResolver;
use wacore::libsignal::store::sender_key_name::SenderKeyName;
use wacore::runtime::Runtime;
use wacore::send::{
    DmStanzaRequest, GroupStanzaRequest, ResolvedDmDevices, ResolvedGroupDevices,
    SenderKeyDistributionPolicy, SignalStores, prepare_dm_stanza, prepare_group_stanza,
    retain_skdm_distribution_targets,
};
use wacore::types::jid::JidExt as _;
use wacore::types::message::AddressingMode;
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

/// A finished group `<message>` stanza.
#[derive(Debug, Clone)]
pub struct PreparedGroupSend {
    pub stanza: Vec<u8>,
    /// Devices this send distributed the sender key to. Once the server acks
    /// the stanza, pass them to [`SignalOps::mark_sender_key_distributed`].
    pub distribution_targets: Vec<Jid>,
    /// Users whose devices were reported unregistered while fetching bundles;
    /// the client should refresh their device lists.
    pub stale_device_users: Vec<String>,
    pub phash: Option<String>,
}

struct OwnIdentity {
    pn: Jid,
    lid: Option<Jid>,
    account: Option<wa::ADVSignedDeviceIdentity>,
}

fn sender_key_device_key(group: &str, device: &Jid) -> String {
    format!("{group}\u{0}{device}")
}

impl<S: ServiceStore> SignalOps<S> {
    async fn own_identity(&self) -> Result<OwnIdentity, OpsError> {
        let keys = self.keys().await;
        let pn: Jid = keys
            .own_pn
            .as_deref()
            .ok_or_else(|| OpsError::InvalidInput("device is not paired: own JID unknown".into()))?
            .parse()
            .map_err(|_| OpsError::InvalidInput("stored own JID does not parse".into()))?;
        let lid: Option<Jid> = keys
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
        Ok(OwnIdentity { pn, lid, account })
    }

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
        let OwnIdentity {
            pn: own_jid,
            lid: own_lid,
            account,
        } = self.own_identity().await?;

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

    /// Build a group stanza: a sender-key message for the group plus, for
    /// devices that do not yet hold this device's sender key, the key itself
    /// encrypted pairwise. Membership and addressing come from the resolver.
    pub async fn send_group(
        &self,
        runtime: &dyn Runtime,
        resolver: &dyn SendContextResolver,
        group: &Jid,
        message: &wa::Message,
        message_id: &str,
    ) -> Result<PreparedGroupSend, OpsError> {
        let OwnIdentity {
            pn: own_jid,
            lid: own_lid,
            account,
        } = self.own_identity().await?;
        let own_lid = own_lid.ok_or_else(|| {
            OpsError::InvalidInput("group sends need this device's LID; call set_own_jids".into())
        })?;
        let routing = resolver
            .resolve_group_routing_info(group)
            .await
            .map_err(send_error)?;
        let is_lid_mode = routing.addressing_mode == AddressingMode::Lid;
        let own_sending = if is_lid_mode { &own_lid } else { &own_jid };

        // Same device query as the client's resolve_group_devices: LID-mode
        // members are queried by phone number, then mapped back.
        let mut queries: Vec<Jid> = routing
            .participants
            .iter()
            .map(|jid| {
                if is_lid_mode
                    && jid.is_lid()
                    && let Some(pn) = routing.phone_jid_for_lid_user(&jid.user)
                {
                    return pn.to_non_ad();
                }
                jid.to_non_ad()
            })
            .collect();
        if !routing
            .participants
            .iter()
            .any(|participant| participant.is_same_user_as(own_sending))
        {
            queries.push(own_jid.to_non_ad());
        }
        let mut devices = resolver
            .resolve_devices(&queries)
            .await
            .map_err(send_error)?;
        if is_lid_mode {
            devices = devices
                .into_iter()
                .map(|device| routing.phone_device_jid_into_lid(device))
                .collect();
        }
        wacore::types::jid::sort_dedup_by_device(&mut devices);
        let addressed = ResolvedGroupDevices::new(devices);

        let group_str = group.to_string();
        let lock = self.session_lock();
        let _guard = lock.lock().await;
        let own_chain =
            SenderKeyName::from_parts(&group_str, own_sending.to_protocol_address().as_str());
        // A missing chain means a fresh key: everyone needs it, as in the
        // client's force_skdm path.
        let force = self
            .store()
            .get_sender_key(own_chain.cache_key())
            .await?
            .is_none();
        let targets = if force {
            let mut all = addressed.devices().to_vec();
            retain_skdm_distribution_targets(&mut all, own_sending);
            all
        } else {
            let warm: HashSet<String> = self
                .store()
                .scan_aux(Namespace::SenderKeyDevices, &format!("{group_str}\u{0}"))
                .await?
                .into_iter()
                .collect();
            let is_warm = |jid: &Jid| warm.contains(&sender_key_device_key(&group_str, jid));
            addressed
                .devices()
                .iter()
                .filter(|device| {
                    !device.is_hosted()
                        && !(device.user == own_sending.user && device.device == own_sending.device)
                        // WA Web treats a companion as warm only if its
                        // primary (device 0) is too.
                        && !(is_warm(device) && is_warm(&device.with_device(0)))
                })
                .cloned()
                .collect()
        };

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
        let prepared = prepare_group_stanza(
            runtime,
            &mut signal,
            resolver,
            GroupStanzaRequest {
                group: &routing,
                own_jid: &own_jid,
                own_lid: &own_lid,
                account: account.as_ref(),
                to: group,
                message,
                message_id,
                force_distribution: force,
                distribution_targets: Some(targets),
                distribution_policy: SenderKeyDistributionPolicy::BestEffort,
                phash_devices: Some(&addressed),
                edit: None,
                extra_nodes: &[],
                pre_encoded: None,
            },
        )
        .await
        .map_err(send_error)?;

        let encoded = waproto::codec::message_to_vec(message);
        staged
            .put_aux(
                Namespace::SentMessage,
                &sent_key(group, message_id),
                &encode_sent(&encoded, prepared.message_secret.as_ref()),
            )
            .await?;
        staged.commit().await?;

        let stanza = wacore_binary::marshal(&prepared.node)
            .map_err(|e| OpsError::Send(format!("stanza did not marshal: {e}")))?;
        Ok(PreparedGroupSend {
            stanza,
            distribution_targets: prepared.skdm_devices,
            stale_device_users: prepared.stale_device_users,
            phash: prepared.phash.map(|p| p.to_string()),
        })
    }

    /// Record that the server acked a group send whose stanza carried the
    /// sender key to `devices`. This account's own devices are never recorded
    /// (WA Web's `!isMeDevice`), so they get the key on every send.
    pub async fn mark_sender_key_distributed(
        &self,
        group: &Jid,
        devices: &[Jid],
    ) -> Result<(), OpsError> {
        let OwnIdentity { pn, lid, .. } = self.own_identity().await?;
        let group_str = group.to_string();
        let lock = self.session_lock();
        let _guard = lock.lock().await;
        for device in devices {
            if device.is_same_user_as(&pn)
                || lid.as_ref().is_some_and(|l| device.is_same_user_as(l))
            {
                continue;
            }
            self.store()
                .put_aux(
                    Namespace::SenderKeyDevices,
                    &sender_key_device_key(&group_str, device),
                    &[1],
                )
                .await?;
        }
        Ok(())
    }

    /// Forget which devices hold the sender key for `group`, so the next send
    /// distributes it again. Use after membership changes.
    pub async fn forget_sender_key_devices(&self, group: &Jid) -> Result<(), OpsError> {
        let prefix = format!("{group}\u{0}");
        let lock = self.session_lock();
        let _guard = lock.lock().await;
        let keys = self
            .store()
            .scan_aux(Namespace::SenderKeyDevices, &prefix)
            .await?;
        let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        self.store()
            .delete_aux(Namespace::SenderKeyDevices, &refs)
            .await?;
        Ok(())
    }
}
