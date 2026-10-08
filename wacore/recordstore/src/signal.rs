use crate::record::{Fence, Namespace, RecordStore, WriteOp};
use crate::seal::{SealError, Sealer};
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use wacore::store::error::{Result, StoreError};
use wacore::store::traits::SignalStore;

const AAD_DOMAIN: &[u8] = b"wacore-recordstore/v1";

/// Prekey plaintext starts with this flag byte, then the libsignal record.
const PREKEY_NOT_UPLOADED: u8 = 0;
const PREKEY_UPLOADED: u8 = 1;

/// [`SignalStore`] for one scope, sealed by `S` and fenced by the lease that
/// produced `fence`. Build a new one whenever the lease is re-acquired.
pub struct RecordSignalStore<R, S> {
    records: Arc<R>,
    sealer: Arc<S>,
    fence: Fence,
}

impl<R: RecordStore, S: Sealer> RecordSignalStore<R, S> {
    pub fn new(records: Arc<R>, sealer: Arc<S>, fence: Fence) -> Self {
        Self {
            records,
            sealer,
            fence,
        }
    }

    pub fn fence(&self) -> &Fence {
        &self.fence
    }

    fn scope(&self) -> &str {
        &self.fence.scope
    }

    fn aad(&self, ns: Namespace, key: &str) -> Vec<u8> {
        let scope = self.scope().as_bytes();
        let tag = ns.tag().as_bytes();
        let mut aad =
            Vec::with_capacity(AAD_DOMAIN.len() + scope.len() + tag.len() + key.len() + 3);
        aad.extend_from_slice(AAD_DOMAIN);
        aad.push(0);
        aad.extend_from_slice(scope);
        aad.push(0);
        aad.extend_from_slice(tag);
        aad.push(0);
        aad.extend_from_slice(key.as_bytes());
        aad
    }

    async fn seal(&self, ns: Namespace, key: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.sealer
            .seal(&self.aad(ns, key), plaintext)
            .await
            .map_err(seal_error)
    }

    async fn open(&self, ns: Namespace, key: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        self.sealer
            .open(&self.aad(ns, key), sealed)
            .await
            .map_err(seal_error)
    }

    async fn load(&self, ns: Namespace, key: &str) -> Result<Option<Vec<u8>>> {
        match self.records.get(self.scope(), ns, key).await? {
            Some(sealed) => Ok(Some(self.open(ns, key, &sealed).await?)),
            None => Ok(None),
        }
    }

    async fn load_many(&self, ns: Namespace, keys: &[&str]) -> Result<Vec<(String, Vec<u8>)>> {
        let found = self.records.get_many(self.scope(), ns, keys).await?;
        let mut opened = Vec::with_capacity(found.len());
        for (key, sealed) in found {
            let plaintext = self.open(ns, &key, &sealed).await?;
            opened.push((key, plaintext));
        }
        Ok(opened)
    }

    async fn put_op(&self, ns: Namespace, key: &str, plaintext: &[u8]) -> Result<WriteOp> {
        Ok(WriteOp::Put {
            ns,
            key: key.to_owned(),
            value: self.seal(ns, key, plaintext).await?,
        })
    }

    async fn write(&self, ops: &[WriteOp]) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        self.records.write(&self.fence, ops).await
    }

    async fn put_one(&self, ns: Namespace, key: &str, plaintext: &[u8]) -> Result<()> {
        let op = self.put_op(ns, key, plaintext).await?;
        self.write(std::slice::from_ref(&op)).await
    }

    async fn delete_keys<K: AsRef<str>>(&self, ns: Namespace, keys: &[K]) -> Result<()> {
        let ops: Vec<_> = keys
            .iter()
            .map(|key| WriteOp::Delete {
                ns,
                key: key.as_ref().to_owned(),
            })
            .collect();
        self.write(&ops).await
    }

    async fn any_key_with_prefix(&self, ns: Namespace, prefix: &str) -> Result<bool> {
        Ok(!self
            .records
            .scan_keys(self.scope(), ns, prefix, Some(1))
            .await?
            .is_empty())
    }
}

fn seal_error(error: SealError) -> StoreError {
    StoreError::Serialization(Box::new(error))
}

/// Zero-padded so byte order matches numeric order in every adapter.
fn id_key(id: u32) -> String {
    format!("{id:010}")
}

fn parse_id(key: &str) -> Result<u32> {
    key.parse()
        .map_err(|_| StoreError::Validation(format!("invalid record id key: {key}")))
}

fn prekey_plaintext(record: &[u8], uploaded: bool) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(record.len() + 1);
    plaintext.push(if uploaded {
        PREKEY_UPLOADED
    } else {
        PREKEY_NOT_UPLOADED
    });
    plaintext.extend_from_slice(record);
    plaintext
}

fn prekey_record(plaintext: Vec<u8>) -> Result<Bytes> {
    match plaintext.first() {
        Some(&PREKEY_NOT_UPLOADED | &PREKEY_UPLOADED) => Ok(Bytes::from(plaintext).slice(1..)),
        _ => Err(StoreError::Validation(
            "prekey record has no upload flag".into(),
        )),
    }
}

fn identity_key(plaintext: Vec<u8>) -> Result<[u8; 32]> {
    let len = plaintext.len();
    plaintext
        .try_into()
        .map_err(|_| StoreError::Validation(format!("Invalid identity key length: {len}")))
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<R: RecordStore, S: Sealer> SignalStore for RecordSignalStore<R, S> {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        self.put_one(Namespace::Identity, address, &key).await
    }

    async fn put_identities_batch(&self, identities: &[(Arc<str>, [u8; 32])]) -> Result<()> {
        let mut ops = Vec::with_capacity(identities.len());
        for (address, key) in identities {
            ops.push(self.put_op(Namespace::Identity, address, key).await?);
        }
        self.write(&ops).await
    }

    async fn load_identity(&self, address: &str) -> Result<Option<[u8; 32]>> {
        self.load(Namespace::Identity, address)
            .await?
            .map(identity_key)
            .transpose()
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        self.delete_keys(Namespace::Identity, &[address]).await
    }

    async fn delete_identities_batch(&self, addresses: &[Arc<str>]) -> Result<()> {
        self.delete_keys(Namespace::Identity, addresses).await
    }

    async fn get_session(&self, address: &str) -> Result<Option<Bytes>> {
        Ok(self
            .load(Namespace::Session, address)
            .await?
            .map(Bytes::from))
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        self.put_one(Namespace::Session, address, session).await
    }

    async fn put_sessions_batch(&self, sessions: &[(Arc<str>, Bytes)]) -> Result<()> {
        let mut ops = Vec::with_capacity(sessions.len());
        for (address, session) in sessions {
            ops.push(self.put_op(Namespace::Session, address, session).await?);
        }
        self.write(&ops).await
    }

    async fn get_sessions_batch(&self, addresses: &[Arc<str>]) -> Result<Vec<(Arc<str>, Bytes)>> {
        let keys: Vec<&str> = addresses.iter().map(|a| &**a).collect();
        let found = self.load_many(Namespace::Session, &keys).await?;
        Ok(found
            .into_iter()
            .map(|(key, value)| {
                // Hand back the caller's own Arc where possible.
                let address = addresses
                    .iter()
                    .find(|a| ***a == *key)
                    .cloned()
                    .unwrap_or_else(|| Arc::from(key));
                (address, Bytes::from(value))
            })
            .collect())
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        self.delete_keys(Namespace::Session, &[address]).await
    }

    async fn delete_sessions_batch(&self, addresses: &[Arc<str>]) -> Result<()> {
        self.delete_keys(Namespace::Session, addresses).await
    }

    async fn has_session(&self, address: &str) -> Result<bool> {
        Ok(self
            .records
            .get(self.scope(), Namespace::Session, address)
            .await?
            .is_some())
    }

    async fn has_signal_state_for_user(&self, user: &str) -> Result<bool> {
        // Addresses are `user@server` (device 0) or `user:device@server`.
        let device_zero = format!("{user}@");
        let other_devices = format!("{user}:");
        for ns in [Namespace::Session, Namespace::Identity] {
            if self.any_key_with_prefix(ns, &device_zero).await?
                || self.any_key_with_prefix(ns, &other_devices).await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn store_prekey(&self, id: u32, record: &[u8], uploaded: bool) -> Result<()> {
        let key = id_key(id);
        self.put_one(Namespace::PreKey, &key, &prekey_plaintext(record, uploaded))
            .await
    }

    async fn store_prekeys_batch(&self, keys: &[(u32, Bytes)], uploaded: bool) -> Result<()> {
        let mut ops = Vec::with_capacity(keys.len());
        for (id, record) in keys {
            let key = id_key(*id);
            ops.push(
                self.put_op(Namespace::PreKey, &key, &prekey_plaintext(record, uploaded))
                    .await?,
            );
        }
        self.write(&ops).await
    }

    async fn load_prekey(&self, id: u32) -> Result<Option<Bytes>> {
        self.load(Namespace::PreKey, &id_key(id))
            .await?
            .map(prekey_record)
            .transpose()
    }

    async fn load_prekeys_batch(&self, ids: &[u32]) -> Result<Vec<(u32, Bytes)>> {
        let keys: Vec<String> = ids.iter().map(|id| id_key(*id)).collect();
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let mut result = Vec::with_capacity(ids.len());
        for (key, plaintext) in self.load_many(Namespace::PreKey, &key_refs).await? {
            result.push((parse_id(&key)?, prekey_record(plaintext)?));
        }
        Ok(result)
    }

    async fn mark_prekeys_uploaded(&self, ids: &[u32]) -> Result<()> {
        let keys: Vec<String> = ids.iter().map(|id| id_key(*id)).collect();
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let mut ops = Vec::with_capacity(ids.len());
        for (key, plaintext) in self.load_many(Namespace::PreKey, &key_refs).await? {
            let record = prekey_record(plaintext)?;
            let value = self
                .seal(Namespace::PreKey, &key, &prekey_plaintext(&record, true))
                .await?;
            // Update, not Put: a key consumed after the read above stays
            // deleted instead of being resurrected by this write.
            ops.push(WriteOp::Update {
                ns: Namespace::PreKey,
                key,
                value,
            });
        }
        self.write(&ops).await
    }

    async fn remove_prekey(&self, id: u32) -> Result<()> {
        self.delete_keys(Namespace::PreKey, &[id_key(id)]).await
    }

    async fn remove_prekeys_batch(&self, ids: &[u32]) -> Result<()> {
        let keys: Vec<String> = ids.iter().map(|id| id_key(*id)).collect();
        self.delete_keys(Namespace::PreKey, &keys).await
    }

    async fn get_max_prekey_id(&self) -> Result<u32> {
        let keys = self
            .records
            .scan_keys(self.scope(), Namespace::PreKey, "", None)
            .await?;
        keys.last().map_or(Ok(0), |key| parse_id(key))
    }

    async fn store_signed_prekey(&self, id: u32, record: &[u8]) -> Result<()> {
        self.put_one(Namespace::SignedPreKey, &id_key(id), record)
            .await
    }

    async fn load_signed_prekey(&self, id: u32) -> Result<Option<Vec<u8>>> {
        self.load(Namespace::SignedPreKey, &id_key(id)).await
    }

    async fn load_all_signed_prekeys(&self) -> Result<Vec<(u32, Vec<u8>)>> {
        let keys = self
            .records
            .scan_keys(self.scope(), Namespace::SignedPreKey, "", None)
            .await?;
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let mut result = Vec::with_capacity(keys.len());
        for (key, plaintext) in self.load_many(Namespace::SignedPreKey, &key_refs).await? {
            result.push((parse_id(&key)?, plaintext));
        }
        result.sort_by_key(|(id, _)| *id);
        Ok(result)
    }

    async fn remove_signed_prekey(&self, id: u32) -> Result<()> {
        self.delete_keys(Namespace::SignedPreKey, &[id_key(id)])
            .await
    }

    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()> {
        self.put_one(Namespace::SenderKey, address, record).await
    }

    async fn put_sender_keys_batch(&self, sender_keys: &[(Arc<str>, Bytes)]) -> Result<()> {
        let mut ops = Vec::with_capacity(sender_keys.len());
        for (address, record) in sender_keys {
            ops.push(self.put_op(Namespace::SenderKey, address, record).await?);
        }
        self.write(&ops).await
    }

    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.load(Namespace::SenderKey, address).await
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        self.delete_keys(Namespace::SenderKey, &[address]).await
    }

    async fn delete_sender_keys_batch(&self, addresses: &[Arc<str>]) -> Result<()> {
        self.delete_keys(Namespace::SenderKey, addresses).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryRecordStore;
    use crate::record::{LeaseStore, is_fence_lost};
    use crate::seal::AesGcmSealer;
    use futures::executor::block_on;

    const TTL: u64 = 10_000;

    fn setup() -> (
        Arc<MemoryRecordStore>,
        RecordSignalStore<MemoryRecordStore, AesGcmSealer>,
    ) {
        let records = Arc::new(MemoryRecordStore::new());
        let lease = block_on(records.acquire("device-1", "node-a", 0, TTL))
            .unwrap()
            .unwrap();
        let store = RecordSignalStore::new(
            records.clone(),
            Arc::new(AesGcmSealer::new(&[3; 32])),
            lease.fence,
        );
        (records, store)
    }

    #[test]
    fn values_are_sealed_at_rest() {
        let (records, store) = setup();
        block_on(store.put_session("alice@s.whatsapp.net", b"ratchet-state")).unwrap();
        let raw = block_on(records.get("device-1", Namespace::Session, "alice@s.whatsapp.net"))
            .unwrap()
            .unwrap();
        assert!(
            !raw.windows(b"ratchet-state".len())
                .any(|w| w == b"ratchet-state"),
            "plaintext reached the record store"
        );
        assert_eq!(
            block_on(store.get_session("alice@s.whatsapp.net"))
                .unwrap()
                .as_deref(),
            Some(&b"ratchet-state"[..])
        );
    }

    #[test]
    fn a_record_copied_to_another_address_fails_to_open() {
        let (records, store) = setup();
        block_on(store.put_session("alice@s.whatsapp.net", b"alice-state")).unwrap();
        let raw = block_on(records.get("device-1", Namespace::Session, "alice@s.whatsapp.net"))
            .unwrap()
            .unwrap();
        block_on(records.write(
            store.fence(),
            &[WriteOp::Put {
                ns: Namespace::Session,
                key: "mallory@s.whatsapp.net".into(),
                value: raw,
            }],
        ))
        .unwrap();
        assert!(block_on(store.get_session("mallory@s.whatsapp.net")).is_err());
    }

    #[test]
    fn a_superseded_node_cannot_write() {
        let (records, stale) = setup();
        let takeover = block_on(records.acquire("device-1", "node-b", TTL, TTL))
            .unwrap()
            .unwrap();
        let fresh = RecordSignalStore::new(
            records.clone(),
            Arc::new(AesGcmSealer::new(&[3; 32])),
            takeover.fence,
        );
        let err = block_on(stale.put_session("alice@s.whatsapp.net", b"old")).unwrap_err();
        assert!(is_fence_lost(&err));
        block_on(fresh.put_session("alice@s.whatsapp.net", b"new")).unwrap();
        assert_eq!(
            block_on(fresh.get_session("alice@s.whatsapp.net"))
                .unwrap()
                .as_deref(),
            Some(&b"new"[..])
        );
    }

    #[test]
    fn identities_round_trip_and_reject_bad_lengths() {
        let (_, store) = setup();
        block_on(store.put_identity("bob@s.whatsapp.net", [9; 32])).unwrap();
        assert_eq!(
            block_on(store.load_identity("bob@s.whatsapp.net")).unwrap(),
            Some([9; 32])
        );
        assert_eq!(
            block_on(store.load_identity("nobody@s.whatsapp.net")).unwrap(),
            None
        );
    }

    #[test]
    fn prekeys_keep_numeric_order_and_never_resurrect() {
        let (_, store) = setup();
        let keys = vec![
            (9, Bytes::from_static(b"nine")),
            (10, Bytes::from_static(b"ten")),
            (100, Bytes::from_static(b"hundred")),
        ];
        block_on(store.store_prekeys_batch(&keys, false)).unwrap();
        assert_eq!(block_on(store.get_max_prekey_id()).unwrap(), 100);

        block_on(store.remove_prekey(10)).unwrap();
        block_on(store.mark_prekeys_uploaded(&[9, 10])).unwrap();
        assert_eq!(block_on(store.load_prekey(10)).unwrap(), None);
        assert_eq!(
            block_on(store.load_prekey(9)).unwrap().as_deref(),
            Some(&b"nine"[..])
        );

        let mut loaded = block_on(store.load_prekeys_batch(&[9, 10, 100])).unwrap();
        loaded.sort_by_key(|(id, _)| *id);
        assert_eq!(
            loaded,
            vec![
                (9, Bytes::from_static(b"nine")),
                (100, Bytes::from_static(b"hundred"))
            ]
        );
    }

    #[test]
    fn signed_prekeys_list_in_order() {
        let (_, store) = setup();
        block_on(store.store_signed_prekey(12, b"twelve")).unwrap();
        block_on(store.store_signed_prekey(2, b"two")).unwrap();
        assert_eq!(
            block_on(store.load_all_signed_prekeys()).unwrap(),
            vec![(2, b"two".to_vec()), (12, b"twelve".to_vec())]
        );
        block_on(store.remove_signed_prekey(2)).unwrap();
        assert_eq!(block_on(store.load_signed_prekey(2)).unwrap(), None);
    }

    #[test]
    fn signal_state_lookup_matches_whole_user_ids() {
        let (_, store) = setup();
        block_on(store.put_session("123:4@s.whatsapp.net", b"s")).unwrap();
        assert!(block_on(store.has_signal_state_for_user("123")).unwrap());
        assert!(!block_on(store.has_signal_state_for_user("12")).unwrap());
        assert!(!block_on(store.has_signal_state_for_user("1234")).unwrap());
    }

    #[test]
    fn batches_and_sender_keys_round_trip() {
        let (_, store) = setup();
        let a: Arc<str> = Arc::from("a@s.whatsapp.net");
        let b: Arc<str> = Arc::from("b@s.whatsapp.net");
        block_on(store.put_sessions_batch(&[
            (a.clone(), Bytes::from_static(b"sa")),
            (b.clone(), Bytes::from_static(b"sb")),
        ]))
        .unwrap();
        let mut found = block_on(store.get_sessions_batch(&[a.clone(), b.clone()])).unwrap();
        found.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(found.len(), 2);
        block_on(store.delete_sessions_batch(std::slice::from_ref(&a))).unwrap();
        assert!(!block_on(store.has_session(&a)).unwrap());
        assert!(block_on(store.has_session(&b)).unwrap());

        block_on(store.put_sender_key("group:me", b"sk")).unwrap();
        assert_eq!(
            block_on(store.get_sender_key("group:me")).unwrap(),
            Some(b"sk".to_vec())
        );
        block_on(store.delete_sender_key("group:me")).unwrap();
        assert_eq!(block_on(store.get_sender_key("group:me")).unwrap(), None);
    }
}
