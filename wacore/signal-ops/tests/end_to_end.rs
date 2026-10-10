//! Two linked devices talking through real Signal sessions, each keeping its
//! state in a sealed, fenced record store.

use futures::executor::block_on;
use std::sync::Arc;
use wacore::libsignal::protocol::{DeviceId, ProtocolAddress};
use wacore::store::traits::SignalStore;
use wacore_recordstore::{
    AesGcmSealer, LeaseStore, MemoryRecordStore, Namespace, RecordSignalStore, RecordStore,
};
mod common;
use common::pair_success_container;
use wacore_signal_ops::{EncKind, OpsError, RemoteBundle, SignalOps};

type Store = RecordSignalStore<MemoryRecordStore, AesGcmSealer>;

const TTL: u64 = 60_000;
const DATA_KEY: [u8; 32] = [42; 32];

struct Node {
    records: Arc<MemoryRecordStore>,
    scope: &'static str,
    ops: SignalOps<Store>,
}

fn store_for(records: &Arc<MemoryRecordStore>, scope: &str, holder: &str, now: u64) -> Arc<Store> {
    let lease = block_on(records.acquire(scope, holder, now, TTL))
        .unwrap()
        .expect("lease available");
    Arc::new(RecordSignalStore::new(
        records.clone(),
        Arc::new(AesGcmSealer::new(&DATA_KEY)),
        lease.fence,
    ))
}

fn new_device(scope: &'static str) -> Node {
    let records = Arc::new(MemoryRecordStore::new());
    let store = store_for(&records, scope, "node-a", 0);
    let ops = block_on(SignalOps::create(store)).unwrap();
    Node {
        records,
        scope,
        ops,
    }
}

fn address(user: &str) -> ProtocolAddress {
    ProtocolAddress::new(&format!("{user}@s.whatsapp.net"), DeviceId::from(1))
}

/// What the WhatsApp client would fetch from the server for `node`.
fn bundle_for(node: &Node, with_prekey: bool) -> (RemoteBundle, Option<u32>) {
    let identity = block_on(node.ops.public_identity());
    let prekey = with_prekey.then(|| {
        let keys = block_on(node.ops.generate_prekeys(1)).unwrap();
        (keys[0].id, keys[0].public_key)
    });
    (
        RemoteBundle {
            registration_id: identity.registration_id,
            device_id: 1,
            identity_key: identity.identity_key,
            signed_prekey_id: identity.signed_prekey.id,
            signed_prekey: identity.signed_prekey.public_key,
            signed_prekey_signature: identity.signed_prekey.signature,
            prekey,
        },
        prekey.map(|(id, _)| id),
    )
}

fn raw_records_contain(node: &Node, needle: &[u8]) -> bool {
    Namespace::ALL.iter().any(|ns| {
        let keys = block_on(node.records.scan_keys(node.scope, *ns, "", None)).unwrap();
        keys.iter().any(|key| {
            let raw = block_on(node.records.get(node.scope, *ns, key))
                .unwrap()
                .unwrap();
            raw.windows(needle.len()).any(|w| w == needle)
        })
    })
}

#[test]
fn a_session_runs_both_ways_and_stays_sealed() {
    let alice = new_device("alice-device");
    let bob = new_device("bob-device");
    let (alice_addr, bob_addr) = (address("111"), address("222"));

    let (bundle, prekey_id) = bundle_for(&bob, true);
    block_on(alice.ops.establish_session(&bob_addr, &bundle)).unwrap();

    let first = block_on(alice.ops.encrypt(&bob_addr, b"hello bob")).unwrap();
    assert_eq!(first.kind, EncKind::PreKey);
    let opened = block_on(bob.ops.decrypt(&alice_addr, first.kind, &first.ciphertext)).unwrap();
    assert_eq!(opened.plaintext, b"hello bob");

    // The consumed one-time prekey is gone, after the session became durable.
    let bob_store = store_for(&bob.records, bob.scope, "node-a", 1);
    assert_eq!(
        block_on(bob_store.load_prekey(prekey_id.unwrap())).unwrap(),
        None
    );

    let reply = block_on(bob.ops.encrypt(&alice_addr, b"hi alice")).unwrap();
    assert_eq!(reply.kind, EncKind::Message);
    let opened = block_on(alice.ops.decrypt(&bob_addr, reply.kind, &reply.ciphertext)).unwrap();
    assert_eq!(opened.plaintext, b"hi alice");

    for round in 0..5u8 {
        let to_bob = block_on(alice.ops.encrypt(&bob_addr, &[b'a', round])).unwrap();
        let got = block_on(
            bob.ops
                .decrypt(&alice_addr, to_bob.kind, &to_bob.ciphertext),
        )
        .unwrap();
        assert_eq!(got.plaintext, [b'a', round]);
        let to_alice = block_on(bob.ops.encrypt(&alice_addr, &[b'b', round])).unwrap();
        let got = block_on(
            alice
                .ops
                .decrypt(&bob_addr, to_alice.kind, &to_alice.ciphertext),
        )
        .unwrap();
        assert_eq!(got.plaintext, [b'b', round]);
    }

    assert!(!raw_records_contain(&bob, b"hello bob"));
    let bob_identity = block_on(bob.ops.public_identity());
    assert!(
        !raw_records_contain(&bob, &bob_identity.adv_secret),
        "device secrets reached the store unsealed"
    );
}

#[test]
fn a_failed_over_node_keeps_the_session_and_the_old_node_is_fenced_out() {
    let alice = new_device("alice-failover");
    let bob = new_device("bob-failover");
    let (alice_addr, bob_addr) = (address("111"), address("222"));
    let (bundle, _) = bundle_for(&bob, true);
    block_on(alice.ops.establish_session(&bob_addr, &bundle)).unwrap();
    let first = block_on(alice.ops.encrypt(&bob_addr, b"before failover")).unwrap();
    block_on(bob.ops.decrypt(&alice_addr, first.kind, &first.ciphertext)).unwrap();

    // node-a's lease lapses; node-b takes the scope from the same records.
    let takeover = store_for(&bob.records, bob.scope, "node-b", TTL + 1);
    let bob_b = block_on(SignalOps::open(takeover)).unwrap();

    let next = block_on(alice.ops.encrypt(&bob_addr, b"after failover")).unwrap();
    let stale = block_on(bob.ops.decrypt(&alice_addr, next.kind, &next.ciphertext));
    let err = stale.expect_err("the superseded node must not advance the ratchet");
    assert!(err.is_fence_lost(), "unexpected error: {err:?}");

    let opened = block_on(bob_b.decrypt(&alice_addr, next.kind, &next.ciphertext)).unwrap();
    assert_eq!(opened.plaintext, b"after failover");
}

#[test]
fn group_messages_decrypt_with_a_distributed_sender_key() {
    let alice = new_device("alice-group");
    let bob = new_device("bob-group");
    let (alice_addr, bob_addr) = (address("111"), address("222"));
    let group = "120363000000001@g.us";
    let (bundle, _) = bundle_for(&bob, true);
    block_on(alice.ops.establish_session(&bob_addr, &bundle)).unwrap();

    let skdm = block_on(alice.ops.sender_key_distribution(group, &alice_addr)).unwrap();
    let carried = block_on(alice.ops.encrypt(&bob_addr, &skdm)).unwrap();
    let received = block_on(
        bob.ops
            .decrypt(&alice_addr, carried.kind, &carried.ciphertext),
    )
    .unwrap();
    block_on(
        bob.ops
            .process_sender_key_distribution(group, &alice_addr, &received.plaintext),
    )
    .unwrap();

    let skmsg = block_on(alice.ops.group_encrypt(group, &alice_addr, b"hello group")).unwrap();
    let plaintext = block_on(bob.ops.group_decrypt(group, &alice_addr, &skmsg)).unwrap();
    assert_eq!(plaintext, b"hello group");
}

#[test]
fn a_prekey_message_for_a_rotated_signed_prekey_still_decrypts() {
    let alice = new_device("alice-rotate");
    let bob = new_device("bob-rotate");
    let (alice_addr, bob_addr) = (address("111"), address("222"));
    let (bundle, _) = bundle_for(&bob, false);
    let before = block_on(bob.ops.public_identity()).signed_prekey;
    block_on(alice.ops.establish_session(&bob_addr, &bundle)).unwrap();

    let after = block_on(bob.ops.rotate_signed_prekey()).unwrap();
    assert_ne!(after.id, before.id);

    let first = block_on(alice.ops.encrypt(&bob_addr, b"old signed prekey")).unwrap();
    let opened = block_on(bob.ops.decrypt(&alice_addr, first.kind, &first.ciphertext)).unwrap();
    assert_eq!(opened.plaintext, b"old signed prekey");
}

#[test]
fn reopening_a_scope_restores_the_same_device() {
    let bob = new_device("bob-reopen");
    let identity = block_on(bob.ops.public_identity());
    let reopened = block_on(SignalOps::open(store_for(
        &bob.records,
        bob.scope,
        "node-a",
        1,
    )))
    .unwrap();
    assert_eq!(block_on(reopened.public_identity()), identity);
    let again = block_on(SignalOps::create(store_for(
        &bob.records,
        bob.scope,
        "node-a",
        2,
    )));
    assert!(
        matches!(again, Err(OpsError::InvalidInput(_))),
        "create overwrote existing keys"
    );
}

#[test]
fn pairing_signs_a_valid_container_with_the_device_prefix() {
    let bob = new_device("bob-pairing-ok");
    let identity = block_on(bob.ops.public_identity());
    let (container, account) =
        pair_success_container(identity.identity_key, &identity.adv_secret, 7);

    let signed = block_on(bob.ops.sign_pairing(&container)).unwrap();
    assert_eq!(signed.key_index, 7);

    let decoded =
        waproto::codec::adv_signed_device_identity_decode(&signed.signed_identity).unwrap();
    let details = decoded.details.as_deref().unwrap();
    let message = [
        &[6u8, 1][..],
        details,
        &identity.identity_key,
        account.public_key.public_key_bytes(),
    ]
    .concat();
    let device_key =
        wacore::libsignal::protocol::PublicKey::from_djb_public_key_bytes(&identity.identity_key)
            .unwrap();
    assert!(device_key.verify_signature(&message, decoded.device_signature.as_deref().unwrap()));
}

#[test]
fn pairing_refuses_a_container_for_another_secret() {
    let bob = new_device("bob-pairing-secret");
    let identity = block_on(bob.ops.public_identity());
    let (container, _) = pair_success_container(identity.identity_key, &[1; 32], 7);
    assert!(matches!(
        block_on(bob.ops.sign_pairing(&container)),
        Err(OpsError::Pairing { code: 401, .. })
    ));
}

#[test]
fn pairing_refuses_a_forged_container() {
    let bob = new_device("bob-pairing");
    let refused = block_on(bob.ops.sign_pairing(b"not a pairing container"));
    assert!(matches!(refused, Err(OpsError::Pairing { .. })));
}

#[test]
fn forget_user_drops_every_device_of_that_user_only() {
    let records = Arc::new(MemoryRecordStore::new());
    let store = store_for(&records, "forget", "node-a", 0);
    let ops = block_on(SignalOps::create(store.clone())).unwrap();
    let forgotten = ["123@c.us.0", "123:7@c.us.0", "123:12@c.us.0"];
    let kept = ["1234@c.us.0", "1234:7@c.us.0", "123@lid.0", "123:7@lid.0"];
    // Stored addresses use WA Web's `c.us` server for phone-number users.
    for address in forgotten.iter().chain(&kept) {
        block_on(store.put_session(address, b"session")).unwrap();
        block_on(store.put_identity(address, [9; 32])).unwrap();
    }

    let user: wacore_binary::Jid = "123:7@s.whatsapp.net".parse().unwrap();
    block_on(ops.forget_user(&user)).unwrap();

    for address in forgotten {
        assert!(
            block_on(store.get_session(address)).unwrap().is_none(),
            "{address}"
        );
        assert!(
            block_on(store.load_identity(address)).unwrap().is_none(),
            "{address}"
        );
    }
    for address in kept {
        assert!(
            block_on(store.get_session(address)).unwrap().is_some(),
            "{address}"
        );
        assert!(
            block_on(store.load_identity(address)).unwrap().is_some(),
            "{address}"
        );
    }
    // Nothing left to forget is not an error.
    block_on(ops.forget_user(&user)).unwrap();
}
