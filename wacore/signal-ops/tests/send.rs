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
    ops.set_own_jids(own_pn, None).await.unwrap();
    ops
}

/// Stands in for the WhatsApp client: answers device-list and prekey
/// queries from a fixed table, as the runner would from the server.
struct FakeClient {
    devices: Vec<Jid>,
    bundles: HashMap<Jid, PreKeyBundle>,
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
        anyhow::bail!("not a group test")
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

/// The `<enc>` addressed to `device` inside a marshaled stanza.
fn enc_for(stanza: &[u8], device: &Jid) -> (String, u8, Vec<u8>) {
    let node = wacore_binary::marshal::unmarshal_packed_ref(stanza)
        .unwrap()
        .to_owned();
    let participants = node.get_optional_child("participants").expect("fan-out");
    let to = participants
        .get_children_by_tag("to")
        .find(|to| {
            to.attrs().optional_string("jid").as_deref() == Some(device.to_string().as_str())
        })
        .expect("an entry for the device");
    let enc = to.get_optional_child("enc").expect("enc");
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
    };
    let to: Jid = "222@s.whatsapp.net".parse().unwrap();
    assert!(
        ops.send_direct(&TokioRuntime, &client, &to, &text("x"), "ID")
            .await
            .is_err()
    );
}
