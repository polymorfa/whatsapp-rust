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
use crate::ops::RemoteBundle;
use crate::ops::{ServiceStore, SignalOps, chain_key, group_key, session_key};
use std::collections::HashSet;
use wacore::client::context::SendContextResolver;
use wacore::libsignal::protocol::{UsePQRatchet, process_prekey_bundle};
use wacore::libsignal::store::sender_key_name::SenderKeyName;
use wacore::runtime::Runtime;
use wacore::send::{
    DmSignalAddressing, DmStanzaRequest, GroupStanzaRequest, ResolvedDmDevices,
    ResolvedGroupDevices, SenderKeyDistributionPolicy, SignalStores, prepare_dm_stanza,
    prepare_group_stanza, retain_skdm_distribution_targets,
};
use wacore::send::{PairwiseRetryDestination, PairwiseRetryRequest, prepare_pairwise_retry_stanza};
use wacore::types::jid::JidExt as _;
use wacore::types::message::{AddressingMode, EditAttribute};
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

/// Sent-message record: `[inserted ms, u64 BE][has_secret][secret (32 bytes,
/// when set)][message]`.
fn encode_sent(message: &[u8], secret: Option<&[u8; 32]>) -> Vec<u8> {
    let inserted_ms = u64::try_from(wacore::time::now_utc().timestamp_millis()).unwrap_or(0);
    let mut out = Vec::with_capacity(8 + 1 + 32 + message.len());
    out.extend_from_slice(&inserted_ms.to_be_bytes());
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

/// `(inserted ms, message bytes)` of a sent-message record.
fn decode_sent(record: &[u8]) -> Result<(u64, &[u8]), OpsError> {
    let corrupt = || OpsError::InvalidInput("sent-message record is corrupt".into());
    let (inserted, rest) = record.split_at_checked(8).ok_or_else(corrupt)?;
    let inserted_ms = u64::from_be_bytes(inserted.try_into().map_err(|_| corrupt())?);
    let body = match rest.first() {
        Some(0) => &rest[1..],
        Some(1) if rest.len() >= 33 => &rest[33..],
        _ => return Err(corrupt()),
    };
    Ok((inserted_ms, body))
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

/// Where a retried message goes, matching the client's retransmission routes.
#[derive(Debug, Clone)]
pub enum RetryRoute {
    /// A direct message; `recipient` is the original chat user when the
    /// requester is one of this account's own devices.
    Direct {
        recipient: Option<Jid>,
    },
    Group {
        addressing_mode: AddressingMode,
    },
    BroadcastList,
}

/// A retry receipt the client received for a message this device sent.
#[derive(Debug, Clone)]
pub struct RetryRequest<'a> {
    /// The chat the original went to (the recipient user, group or list).
    pub chat: &'a Jid,
    pub message_id: &'a str,
    /// The device that asked, as addressed on the wire.
    pub requester: &'a Jid,
    /// The address to encrypt to (the requester's LID when known).
    pub encryption_jid: &'a Jid,
    pub route: RetryRoute,
    pub retry_count: u8,
    /// Keys the receipt carried, used to start a fresh session.
    pub bundle: Option<&'a RemoteBundle>,
}

struct OwnIdentity {
    pn: Jid,
    lid: Option<Jid>,
    account: Option<wa::ADVSignedDeviceIdentity>,
}

/// The address a device is encrypted to: its LID when the client knows the
/// mapping for a phone-number device, otherwise the device itself.
async fn encryption_jid(resolver: &dyn SendContextResolver, device: &Jid) -> Jid {
    if device.is_pn()
        && let Some(lid_user) = resolver.get_lid_for_phone(&device.user).await
        && let Ok(lid) = format!("{lid_user}@lid").parse::<Jid>()
    {
        return lid.with_device(device.device);
    }
    device.clone()
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

        // Fix each device's Signal address up front (its LID when the client
        // knows one, as wacore's fan-out would) so the locks taken here cover
        // exactly the sessions the encrypt will write.
        let mut encryption = Vec::with_capacity(resolved.devices().len());
        for device in resolved.devices() {
            encryption.push(encryption_jid(resolver, device).await);
        }
        let held_keys: Vec<String> = encryption
            .iter()
            .map(|jid| session_key(&jid.to_protocol_address()))
            .collect();
        let mut lock_jids = encryption.clone();
        lock_jids.sort_by_key(|jid| jid.to_protocol_address().as_str().to_owned());
        let _ = resolved.signal_addressing_or_init(DmSignalAddressing::new(encryption, lock_jids));
        let _held = self.lock_keys(held_keys).await;
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
        let (_, body) = decode_sent(&record)?;
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
        let mut held_keys = vec![
            chain_key(&group_str, own_sending.to_protocol_address().as_str()),
            group_key(&group_str),
        ];
        for device in addressed.devices() {
            held_keys.push(session_key(&device.to_protocol_address()));
            held_keys.push(session_key(
                &encryption_jid(resolver, device).await.to_protocol_address(),
            ));
        }
        let _held = self.lock_keys(held_keys).await;
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
        let _held = self.lock_keys(vec![group_key(&group_str)]).await;
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
        let _held = self.lock_keys(vec![group_key(&group.to_string())]).await;
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

    /// Re-encrypt a sent message for the device that asked for it. Without a
    /// session and without keys in the receipt, a bundle is fetched through
    /// the resolver, as the client does. Status messages are not handled here.
    pub async fn resend(
        &self,
        resolver: &dyn SendContextResolver,
        request: RetryRequest<'_>,
    ) -> Result<Vec<u8>, OpsError> {
        let message = self
            .sent_message(request.chat, request.message_id)
            .await?
            .ok_or_else(|| OpsError::InvalidInput("no record of that sent message".into()))?;
        let OwnIdentity { account, .. } = self.own_identity().await?;
        let address = request.encryption_jid.to_protocol_address();

        let _held = self.lock_keys(vec![session_key(&address)]).await;
        let staged = std::sync::Arc::new(self.store().staged());
        if let Some(bundle) = request.bundle {
            self.establish_into(&staged, &address, bundle).await?;
        } else if !staged.has_session(address.as_str()).await? {
            let fetched = resolver
                .fetch_prekeys(std::slice::from_ref(request.encryption_jid))
                .await
                .map_err(send_error)?;
            let bundle = fetched.get(request.encryption_jid).ok_or_else(|| {
                OpsError::Send("no session and no prekey bundle for the requester".into())
            })?;
            let mut sessions = self.stores_over(staged.clone()).await;
            let mut identities = sessions.clone();
            process_prekey_bundle(
                &address,
                &mut sessions,
                &mut identities,
                bundle,
                &mut rand::make_rng::<rand::rngs::StdRng>(),
                UsePQRatchet::No,
            )
            .await?;
        }

        let destination = match request.route {
            RetryRoute::Direct { recipient } => PairwiseRetryDestination::Direct {
                to: request.requester.clone(),
                recipient,
            },
            RetryRoute::Group { addressing_mode } => PairwiseRetryDestination::Participant {
                to: request.chat.clone(),
                participant: request.requester.clone(),
                addressing_mode: Some(addressing_mode),
            },
            RetryRoute::BroadcastList => PairwiseRetryDestination::Participant {
                to: request.chat.clone(),
                participant: request.requester.clone(),
                addressing_mode: None,
            },
        };
        let mut sessions = self.stores_over(staged.clone()).await;
        let mut identities = sessions.clone();
        let node = prepare_pairwise_retry_stanza(
            &mut sessions,
            &mut identities,
            PairwiseRetryRequest {
                destination,
                encryption_jid: request.encryption_jid.clone(),
                message: &message,
                message_id: request.message_id.to_owned(),
                retry_count: request.retry_count,
                account: account.as_ref(),
                edit: EditAttribute::infer_from_message(&message),
                pre_encoded: None,
            },
        )
        .await
        .map_err(send_error)?;
        staged.commit().await?;
        wacore_binary::marshal(&node)
            .map_err(|e| OpsError::Send(format!("stanza did not marshal: {e}")))
    }

    /// Delete sent-message records inserted before `cutoff_ms`; a retry
    /// receipt for an older message can no longer be answered. Returns how
    /// many were removed.
    pub async fn prune_sent_messages(&self, cutoff_ms: u64) -> Result<usize, OpsError> {
        let store = self.store();
        let mut expired = Vec::new();
        for key in store.scan_aux(Namespace::SentMessage, "").await? {
            if let Some(record) = store.load_aux(Namespace::SentMessage, &key).await?
                && decode_sent(&record)?.0 < cutoff_ms
            {
                expired.push(key);
            }
        }
        let refs: Vec<&str> = expired.iter().map(String::as_str).collect();
        store.delete_aux(Namespace::SentMessage, &refs).await?;
        Ok(expired.len())
    }
}
