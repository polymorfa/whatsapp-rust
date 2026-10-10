//! Outbound: the service builds the stanza, the client only resolves devices
//! and bundles, and the recipient decrypts what was built.

use async_trait::async_trait;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use wacore::client::context::{GroupRoutingInfo, SendContextResolver};
use wacore::libsignal::protocol::{DeviceId, IdentityKey, PreKeyBundle, PublicKey};
use wacore::prekeys::PreKeyFetchOutcome;
use wacore::runtime::{AbortHandle, Runtime};
use wacore::types::jid::JidExt as _;
use wacore_binary::{Jid, NodeContent};
use wacore_recordstore::{AesGcmSealer, LeaseStore, MemoryRecordStore, RecordSignalStore};
mod common;
use wacore_signal_ops::{ReceiveKind, ReceiveRequest, Received, SignalOps};
use waproto::whatsapp as wa;

type Store = RecordSignalStore<MemoryRecordStore, AesGcmSealer>;
type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn spawn(&self, future: BoxFuture) -> AbortHandle {
        let task = tokio::spawn(future);
        AbortHandle::new(move || task.abort())
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn spawn_blocking(&self, f: Box<dyn FnOnce() + Send + 'static>) -> BoxFuture {
        Box::pin(async move {
            let _ = tokio::task::spawn_blocking(f).await;
        })
    }

    fn yield_now(&self) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
        Some(Box::pin(tokio::task::yield_now()))
    }
}

async fn device(scope: &str, own_pn: &str) -> SignalOps<Store> {
    device_with_lid(scope, own_pn, None).await
}

async fn device_with_lid(scope: &str, own_pn: &str, own_lid: Option<&str>) -> SignalOps<Store> {
    let records = Arc::new(MemoryRecordStore::new());
    let lease = records
        .acquire(scope, "node-a", 0, 60_000)
        .await
        .unwrap()
        .unwrap();
    let store = Arc::new(RecordSignalStore::new(
        records,
        Arc::new(AesGcmSealer::new(&[5; 32])),
        lease.fence,
    ));
    let ops = SignalOps::create(store).await.unwrap();
    ops.set_own_jids(own_pn, own_lid).await.unwrap();
    ops
}

/// Stands in for the WhatsApp client: answers device-list and prekey
/// queries from a fixed table, as the runner would from the server.
struct FakeClient {
    devices: Vec<Jid>,
    bundles: HashMap<Jid, PreKeyBundle>,
    group: Option<Arc<GroupRoutingInfo>>,
}

#[async_trait]
impl SendContextResolver for FakeClient {
    async fn resolve_devices(&self, _jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        Ok(self.devices.clone())
    }

    async fn fetch_prekeys(
        &self,
        jids: &[Jid],
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        Ok(jids
            .iter()
            .filter_map(|jid| self.bundles.get(jid).map(|b| (jid.clone(), b.clone())))
            .collect())
    }

    async fn fetch_prekeys_for_identity_check(
        &self,
        jids: &[Jid],
    ) -> Result<PreKeyFetchOutcome, anyhow::Error> {
        Ok(PreKeyFetchOutcome {
            bundles: self.fetch_prekeys(jids).await?,
            rejected: Vec::new(),
        })
    }

    async fn resolve_group_routing_info(
        &self,
        _jid: &Jid,
    ) -> Result<Arc<GroupRoutingInfo>, anyhow::Error> {
        self.group
            .clone()
            .ok_or_else(|| anyhow::anyhow!("not a group test"))
    }
}

async fn bundle_for(ops: &SignalOps<Store>) -> PreKeyBundle {
    let identity = ops.public_identity().await;
    let prekey = ops.generate_prekeys(1).await.unwrap().remove(0);
    PreKeyBundle::new(
        identity.registration_id,
        DeviceId::from(1),
        Some((
            prekey.id.into(),
            PublicKey::from_djb_public_key_bytes(&prekey.public_key).unwrap(),
        )),
        identity.signed_prekey.id.into(),
        PublicKey::from_djb_public_key_bytes(&identity.signed_prekey.public_key).unwrap(),
        identity.signed_prekey.signature,
        IdentityKey::new(PublicKey::from_djb_public_key_bytes(&identity.identity_key).unwrap()),
    )
    .unwrap()
}

fn parse(stanza: &[u8]) -> wacore_binary::Node {
    wacore_binary::marshal::unmarshal_packed_ref(stanza)
        .unwrap()
        .to_owned()
}

fn enc_parts(enc: &wacore_binary::Node) -> (String, u8, Vec<u8>) {
    let kind = enc.attrs().optional_string("type").unwrap().to_string();
    let version = enc
        .attrs()
        .optional_string("v")
        .map_or(2, |v| v.parse().unwrap());
    let Some(NodeContent::Bytes(bytes)) = &enc.content else {
        panic!("enc without bytes")
    };
    (kind, version, bytes.clone())
}

/// The pairwise `<enc>` addressed to `device`, if the stanza has one.
fn pairwise_enc_for(stanza: &[u8], device: &Jid) -> Option<(String, u8, Vec<u8>)> {
    let node = parse(stanza);
    let participants = node.get_optional_child("participants")?;
    let to = participants.get_children_by_tag("to").find(|to| {
        to.attrs().optional_string("jid").as_deref() == Some(device.to_string().as_str())
    })?;
    Some(enc_parts(to.get_optional_child("enc").expect("enc")))
}

/// The `<enc>` addressed to `device` inside a marshaled stanza.
fn enc_for(stanza: &[u8], device: &Jid) -> (String, u8, Vec<u8>) {
    pairwise_enc_for(stanza, device).expect("an entry for the device")
}

/// The group-wide `skmsg` `<enc>`.
fn skmsg_of(stanza: &[u8]) -> (String, u8, Vec<u8>) {
    let node = parse(stanza);
    let enc = node
        .get_children_by_tag("enc")
        .find(|e| e.attrs().optional_string("type").as_deref() == Some("skmsg"))
        .expect("skmsg");
    enc_parts(enc)
}

fn text(body: &str) -> wa::Message {
    wa::Message {
        conversation: Some(body.to_owned()),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stanza_built_by_the_service_decrypts_at_the_recipient() {
    let alice_jid: Jid = "111:1@s.whatsapp.net".parse().unwrap();
    let bob_jid: Jid = "222:1@s.whatsapp.net".parse().unwrap();
    let alice = device("alice-send", "111:1@s.whatsapp.net").await;
    let bob = device("bob-send", "222:1@s.whatsapp.net").await;
    let client = FakeClient {
        devices: vec![bob_jid.clone()],
        bundles: HashMap::from([(bob_jid.clone(), bundle_for(&bob).await)]),
        group: None,
    };
    let to = bob_jid.to_non_ad();

    for (round, body) in ["first message", "second message"].into_iter().enumerate() {
        let id = format!("MSG{round}");
        let sent = alice
            .send_direct(&TokioRuntime, &client, &to, &text(body), &id)
            .await
            .unwrap();
        assert!(sent.unreached_devices.is_empty());
        let (kind, version, ciphertext) = enc_for(&sent.stanza, &bob_jid);
        // Until the recipient replies, every message on a new session is a
        // prekey message (libsignal's unacknowledged-prekey state).
        assert_eq!(kind, "pkmsg");

        let sender = alice_jid.to_protocol_address();
        let received = bob
            .receive(ReceiveRequest {
                chat: &alice_jid.to_non_ad().to_string(),
                sender: &sender,
                kind: if kind == "pkmsg" {
                    ReceiveKind::PreKey
                } else {
                    ReceiveKind::Message
                },
                ciphertext: &ciphertext,
                padding_version: version,
                is_from_me: false,
            })
            .await
            .unwrap();
        let Received::Message(message) = received else {
            panic!("expected a message")
        };
        assert_eq!(message.content.message.conversation.as_deref(), Some(body));

        let kept = alice.sent_message(&to, &id).await.unwrap().unwrap();
        assert_eq!(kept.conversation.as_deref(), Some(body));
    }

    assert_eq!(alice.prune_sent_messages(0).await.unwrap(), 0);
    assert_eq!(alice.prune_sent_messages(u64::MAX).await.unwrap(), 2);
    assert!(alice.sent_message(&to, "MSG0").await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unpaired_device_refuses_to_send() {
    let records = Arc::new(MemoryRecordStore::new());
    let lease = records
        .acquire("unpaired", "node-a", 0, 60_000)
        .await
        .unwrap()
        .unwrap();
    let ops = SignalOps::create(Arc::new(RecordSignalStore::new(
        records,
        Arc::new(AesGcmSealer::new(&[5; 32])),
        lease.fence,
    )))
    .await
    .unwrap();
    let client = FakeClient {
        devices: Vec::new(),
        bundles: HashMap::new(),
        group: None,
    };
    let to: Jid = "222@s.whatsapp.net".parse().unwrap();
    assert!(
        ops.send_direct(&TokioRuntime, &client, &to, &text("x"), "ID")
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_group_send_distributes_the_sender_key_once_then_reuses_it() {
    use wacore::types::message::AddressingMode;

    let group: Jid = "120363000000001@g.us".parse().unwrap();
    let alice_jid: Jid = "111:1@s.whatsapp.net".parse().unwrap();
    // A primary device, so the primary-device gate is met once it is marked.
    let bob_jid: Jid = "222@s.whatsapp.net".parse().unwrap();
    let alice = device_with_lid(
        "alice-group-send",
        "111:1@s.whatsapp.net",
        Some("900111:1@lid"),
    )
    .await;
    let bob = device("bob-group-send", "222@s.whatsapp.net").await;
    let client = FakeClient {
        devices: vec![alice_jid.clone(), bob_jid.clone()],
        bundles: HashMap::from([(bob_jid.clone(), bundle_for(&bob).await)]),
        group: Some(Arc::new(GroupRoutingInfo::new(
            vec![alice_jid.to_non_ad(), bob_jid.clone()],
            AddressingMode::Pn,
        ))),
    };
    let alice_addr = alice_jid.to_protocol_address();
    let group_str = group.to_string();
    let receive = |kind: &str, version: u8, ciphertext: Vec<u8>| {
        let sender = alice_addr.clone();
        let chat = group_str.clone();
        let kind = match kind {
            "pkmsg" => ReceiveKind::PreKey,
            "msg" => ReceiveKind::Message,
            _ => ReceiveKind::SenderKey,
        };
        let bob = &bob;
        async move {
            bob.receive(ReceiveRequest {
                chat: &chat,
                sender: &sender,
                kind,
                ciphertext: &ciphertext,
                padding_version: version,
                is_from_me: false,
            })
            .await
            .unwrap()
        }
    };

    let first = alice
        .send_group(&TokioRuntime, &client, &group, &text("hello group"), "G1")
        .await
        .unwrap();
    assert_eq!(first.distribution_targets, vec![bob_jid.clone()]);
    let (kind, version, carrier) = pairwise_enc_for(&first.stanza, &bob_jid).expect("key for bob");
    let Received::Message(_) = receive(&kind, version, carrier).await else {
        panic!("sender key carrier was not delivered")
    };
    let (_, version, skmsg) = skmsg_of(&first.stanza);
    let Received::Message(message) = receive("skmsg", version, skmsg).await else {
        panic!("expected the group message")
    };
    assert_eq!(
        message.content.message.conversation.as_deref(),
        Some("hello group")
    );

    alice
        .mark_sender_key_distributed(&group, &first.distribution_targets)
        .await
        .unwrap();
    let second = alice
        .send_group(&TokioRuntime, &client, &group, &text("second"), "G2")
        .await
        .unwrap();
    assert!(second.distribution_targets.is_empty());
    assert!(pairwise_enc_for(&second.stanza, &bob_jid).is_none());
    let (_, version, skmsg) = skmsg_of(&second.stanza);
    let Received::Message(message) = receive("skmsg", version, skmsg).await else {
        panic!("expected the group message")
    };
    assert_eq!(
        message.content.message.conversation.as_deref(),
        Some("second")
    );

    // A retry receipt from Bob in the group makes the next send redistribute.
    common::pair(&alice).await;
    alice
        .resend(
            &client,
            wacore_signal_ops::RetryRequest {
                chat: &group,
                message_id: "G2",
                requester: &bob_jid,
                encryption_jid: &bob_jid,
                route: wacore_signal_ops::RetryRoute::Group {
                    addressing_mode: AddressingMode::Pn,
                },
                retry_count: 1,
                bundle: None,
            },
        )
        .await
        .unwrap();
    let after_retry = alice
        .send_group(&TokioRuntime, &client, &group, &text("after retry"), "G2b")
        .await
        .unwrap();
    assert_eq!(after_retry.distribution_targets, vec![bob_jid.clone()]);
    alice
        .mark_sender_key_distributed(&group, &after_retry.distribution_targets)
        .await
        .unwrap();

    alice.forget_sender_key_devices(&group).await.unwrap();
    let third = alice
        .send_group(&TokioRuntime, &client, &group, &text("third"), "G3")
        .await
        .unwrap();
    assert_eq!(third.distribution_targets, vec![bob_jid.clone()]);
}

/// The first `<enc>` anywhere in the stanza.
fn first_enc(stanza: &[u8]) -> (String, u8, Vec<u8>) {
    fn find(node: &wacore_binary::Node) -> Option<&wacore_binary::Node> {
        if node.tag == "enc" {
            return Some(node);
        }
        node.children()?.iter().find_map(find)
    }
    enc_parts(find(&parse(stanza)).expect("enc"))
}

fn remote_bundle_from(bundle: &PreKeyBundle) -> wacore_signal_ops::RemoteBundle {
    let key = |k: &PublicKey| -> [u8; 32] { k.public_key_bytes().try_into().unwrap() };
    wacore_signal_ops::RemoteBundle {
        registration_id: bundle.registration_id().unwrap(),
        device_id: bundle.device_id().unwrap().into(),
        identity_key: key(bundle.identity_key().unwrap().public_key()),
        signed_prekey_id: bundle.signed_pre_key_id().unwrap().into(),
        signed_prekey: key(&bundle.signed_pre_key_public().unwrap()),
        signed_prekey_signature: bundle
            .signed_pre_key_signature()
            .unwrap()
            .try_into()
            .unwrap(),
        prekey: bundle
            .pre_key_id()
            .unwrap()
            .map(|id| (id.into(), key(&bundle.pre_key_public().unwrap().unwrap()))),
    }
}

/// Decrypt the first `<enc>` of a stanza from `from` and return its text.
async fn deliver(ops: &SignalOps<Store>, from: &Jid, stanza: Vec<u8>) -> Option<String> {
    let (kind, version, ciphertext) = first_enc(&stanza);
    let sender = from.to_protocol_address();
    let chat = from.to_non_ad().to_string();
    let received = ops
        .receive(ReceiveRequest {
            chat: &chat,
            sender: &sender,
            kind: if kind == "pkmsg" {
                ReceiveKind::PreKey
            } else {
                ReceiveKind::Message
            },
            ciphertext: &ciphertext,
            padding_version: version,
            is_from_me: false,
        })
        .await
        .unwrap();
    let Received::Message(message) = received else {
        panic!("expected a message")
    };
    message.content.message.conversation
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retry_receipt_gets_the_message_re_encrypted() {
    use wacore_signal_ops::{RetryRequest, RetryRoute};

    let alice_jid: Jid = "111:1@s.whatsapp.net".parse().unwrap();
    let bob_jid: Jid = "222:1@s.whatsapp.net".parse().unwrap();
    let alice = device("alice-retry", "111:1@s.whatsapp.net").await;
    // A retry pkmsg must carry the device identity, which pairing provides.
    common::pair(&alice).await;
    let bob = device("bob-retry", "222:1@s.whatsapp.net").await;
    let client = FakeClient {
        devices: vec![bob_jid.clone()],
        bundles: HashMap::from([(bob_jid.clone(), bundle_for(&bob).await)]),
        group: None,
    };
    let to = bob_jid.to_non_ad();
    // Bob never processes the original.
    alice
        .send_direct(&TokioRuntime, &client, &to, &text("lost once"), "R1")
        .await
        .unwrap();

    let retried = alice
        .resend(
            &client,
            RetryRequest {
                chat: &to,
                message_id: "R1",
                requester: &bob_jid,
                encryption_jid: &bob_jid,
                route: RetryRoute::Direct { recipient: None },
                retry_count: 1,
                bundle: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        deliver(&bob, &alice_jid, retried).await.as_deref(),
        Some("lost once")
    );

    // Bob's device was reset: new keys arrive with the next retry receipt.
    let fresh_bob = device("bob-retry-fresh", "222:1@s.whatsapp.net").await;
    let fresh_bundle = remote_bundle_from(&bundle_for(&fresh_bob).await);
    let retried = alice
        .resend(
            &client,
            RetryRequest {
                chat: &to,
                message_id: "R1",
                requester: &bob_jid,
                encryption_jid: &bob_jid,
                route: RetryRoute::Direct { recipient: None },
                retry_count: 2,
                bundle: Some(&fresh_bundle),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        deliver(&fresh_bob, &alice_jid, retried).await.as_deref(),
        Some("lost once")
    );

    let unknown = alice
        .resend(
            &client,
            RetryRequest {
                chat: &to,
                message_id: "NOPE",
                requester: &bob_jid,
                encryption_jid: &bob_jid,
                route: RetryRoute::Direct { recipient: None },
                retry_count: 1,
                bundle: None,
            },
        )
        .await;
    assert!(unknown.is_err());
}

/// Holds every prekey fetch until released, like a slow peer lookup.
struct SlowClient {
    inner: FakeClient,
    gate: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl SendContextResolver for SlowClient {
    async fn resolve_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        self.inner.resolve_devices(jids).await
    }

    async fn fetch_prekeys(
        &self,
        jids: &[Jid],
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        self.gate.notified().await;
        self.inner.fetch_prekeys(jids).await
    }

    async fn fetch_prekeys_for_identity_check(
        &self,
        jids: &[Jid],
    ) -> Result<PreKeyFetchOutcome, anyhow::Error> {
        Ok(PreKeyFetchOutcome {
            bundles: self.fetch_prekeys(jids).await?,
            rejected: Vec::new(),
        })
    }

    async fn resolve_group_routing_info(
        &self,
        jid: &Jid,
    ) -> Result<Arc<GroupRoutingInfo>, anyhow::Error> {
        self.inner.resolve_group_routing_info(jid).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_send_does_not_block_receiving_from_another_peer() {
    let alice_jid: Jid = "111:1@s.whatsapp.net".parse().unwrap();
    let carol_jid: Jid = "333:1@s.whatsapp.net".parse().unwrap();
    let dave_jid: Jid = "444:1@s.whatsapp.net".parse().unwrap();
    let alice = device("alice-slow", "111:1@s.whatsapp.net").await;
    let carol = device("carol-slow", "333:1@s.whatsapp.net").await;
    let dave = Arc::new(device("dave-slow", "444:1@s.whatsapp.net").await);

    let gate = Arc::new(tokio::sync::Notify::new());
    let slow = Arc::new(SlowClient {
        inner: FakeClient {
            devices: vec![carol_jid.clone()],
            bundles: HashMap::from([(carol_jid.clone(), bundle_for(&carol).await)]),
            group: None,
        },
        gate: gate.clone(),
    });
    let send = {
        let dave = dave.clone();
        let slow = slow.clone();
        let to = carol_jid.to_non_ad();
        tokio::spawn(async move {
            dave.send_direct(&TokioRuntime, slow.as_ref(), &to, &text("to carol"), "S1")
                .await
        })
    };

    // Alice writes to Dave while Dave's send is stuck fetching Carol's keys.
    let to_dave = FakeClient {
        devices: vec![dave_jid.clone()],
        bundles: HashMap::from([(dave_jid.clone(), bundle_for(&dave).await)]),
        group: None,
    };
    let sent = alice
        .send_direct(
            &TokioRuntime,
            &to_dave,
            &dave_jid.to_non_ad(),
            &text("to dave"),
            "A1",
        )
        .await
        .unwrap();
    let received = tokio::time::timeout(
        Duration::from_secs(5),
        deliver(&dave, &alice_jid, sent.stanza),
    )
    .await
    .expect("receive was blocked by an unrelated send");
    assert_eq!(received.as_deref(), Some("to dave"));

    gate.notify_one();
    send.await.unwrap().unwrap();
}
