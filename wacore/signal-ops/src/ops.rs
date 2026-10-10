use crate::device::{
    DeviceKeys, MAX_PREKEY_ID, PublicIdentity, PublicPreKey, PublicSignedPreKey, public_bytes,
    sign_prekey,
};
use crate::error::OpsError;
use crate::stores::{KeyedLocks, Stores};
use async_lock::{Mutex, RwLock};
use async_trait::async_trait;
use std::sync::Arc;
use wacore::libsignal::protocol::{
    CiphertextMessageType, DeviceId, IdentityKey, KeyPair, PreKeyBundle, PreKeySignalMessage,
    ProtocolAddress, PublicKey, SenderKeyDistributionMessage, SignalMessage, UsePQRatchet,
    create_sender_key_distribution_message, group_decrypt, group_encrypt, message_decrypt_prekey,
    message_decrypt_signal, message_encrypt, process_prekey_bundle,
    process_sender_key_distribution_message,
};
use wacore::libsignal::store::record_helpers;
use wacore::libsignal::store::sender_key_name::SenderKeyName;
use wacore::pair::PairUtils;
use wacore::store::error::Result as StoreResult;
use wacore::store::traits::SignalStore;
use wacore_recordstore::{Namespace, RecordSignalStore, RecordStore, Sealer};

/// Storage the Signal service needs beyond [`SignalStore`]: the device key
/// blob, its own records (decrypt buffer, sent messages), and staged views
/// whose writes commit as one batch.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ServiceStore: SignalStore + Sized + 'static {
    async fn load_device_keys(&self) -> StoreResult<Option<Vec<u8>>>;
    async fn save_device_keys(&self, blob: &[u8]) -> StoreResult<()>;
    /// A view whose writes are held until [`Self::commit`].
    fn staged(&self) -> Self;
    /// Apply a staged view's writes as one fenced batch.
    async fn commit(&self) -> StoreResult<()>;
    async fn load_aux(&self, ns: Namespace, key: &str) -> StoreResult<Option<Vec<u8>>>;
    async fn put_aux(&self, ns: Namespace, key: &str, value: &[u8]) -> StoreResult<()>;
    async fn delete_aux(&self, ns: Namespace, keys: &[&str]) -> StoreResult<()>;
    async fn scan_aux(&self, ns: Namespace, prefix: &str) -> StoreResult<Vec<String>>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<R: RecordStore + 'static, S: Sealer + 'static> ServiceStore for RecordSignalStore<R, S> {
    async fn load_device_keys(&self) -> StoreResult<Option<Vec<u8>>> {
        self.load_device().await
    }

    async fn save_device_keys(&self, blob: &[u8]) -> StoreResult<()> {
        self.save_device(blob).await
    }

    fn staged(&self) -> Self {
        RecordSignalStore::staged(self)
    }

    async fn commit(&self) -> StoreResult<()> {
        RecordSignalStore::commit(self).await
    }

    async fn load_aux(&self, ns: Namespace, key: &str) -> StoreResult<Option<Vec<u8>>> {
        RecordSignalStore::load_aux(self, ns, key).await
    }

    async fn put_aux(&self, ns: Namespace, key: &str, value: &[u8]) -> StoreResult<()> {
        RecordSignalStore::put_aux(self, ns, key, value).await
    }

    async fn delete_aux(&self, ns: Namespace, keys: &[&str]) -> StoreResult<()> {
        RecordSignalStore::delete_aux(self, ns, keys).await
    }

    async fn scan_aux(&self, ns: Namespace, prefix: &str) -> StoreResult<Vec<String>> {
        RecordSignalStore::scan_aux(self, ns, prefix, None).await
    }
}

/// Pairwise ciphertext kinds, named as in the `<enc type>` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncKind {
    /// `pkmsg`: first message of a session, carries X3DH material.
    PreKey,
    /// `msg`: a message on an established session.
    Message,
}

impl EncKind {
    pub fn wire(self) -> &'static str {
        match self {
            EncKind::PreKey => "pkmsg",
            EncKind::Message => "msg",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    /// Padded plaintext exactly as libsignal produced it.
    pub plaintext: Vec<u8>,
    /// The sender's identity key differs from the one stored before.
    pub identity_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    pub kind: EncKind,
    pub ciphertext: Vec<u8>,
}

/// A peer device's prekey bundle, as fetched by the client from the server.
#[derive(Debug, Clone)]
pub struct RemoteBundle {
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_key: [u8; 32],
    pub signed_prekey_id: u32,
    pub signed_prekey: [u8; 32],
    pub signed_prekey_signature: [u8; 64],
    pub prekey: Option<(u32, [u8; 32])>,
}

impl RemoteBundle {
    /// The libsignal bundle, validating every key.
    pub fn to_prekey_bundle(&self) -> Result<PreKeyBundle, OpsError> {
        let prekey = match self.prekey {
            Some((id, key)) => Some((id.into(), public_key(&key, "prekey")?)),
            None => None,
        };
        Ok(PreKeyBundle::new(
            self.registration_id,
            DeviceId::from(self.device_id),
            prekey,
            self.signed_prekey_id.into(),
            public_key(&self.signed_prekey, "signed prekey")?,
            self.signed_prekey_signature,
            IdentityKey::new(public_key(&self.identity_key, "identity key")?),
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingSignature {
    /// `ADVSignedDeviceIdentity` with the device signature added, ready for the
    /// pair-success response.
    pub signed_identity: Vec<u8>,
    pub key_index: u32,
}

/// Signal operations for one scope (one linked device).
///
/// Every operation that changes Signal state holds one lock per device:
/// staged views commit whole batches, so two concurrent views writing the
/// same session would lose a ratchet step. The store's lease fencing protects
/// against a second node.
pub struct SignalOps<S> {
    store: Arc<S>,
    keys: RwLock<Arc<DeviceKeys>>,
    /// Held while device keys are read-modify-written.
    device_write: Mutex<()>,
    session_lock: Arc<Mutex<()>>,
    sender_key_locks: Arc<KeyedLocks>,
}

fn rng() -> rand::rngs::StdRng {
    rand::make_rng::<rand::rngs::StdRng>()
}

fn public_key(bytes: &[u8; 32], what: &str) -> Result<PublicKey, OpsError> {
    PublicKey::from_djb_public_key_bytes(bytes)
        .map_err(|_| OpsError::InvalidInput(format!("{what} is not a valid public key")))
}

impl<S: ServiceStore> SignalOps<S> {
    /// Open a scope that already has device keys.
    pub async fn open(store: Arc<S>) -> Result<Self, OpsError> {
        let blob = store
            .load_device_keys()
            .await?
            .ok_or(OpsError::NotInitialised)?;
        Ok(Self::with_keys(store, DeviceKeys::decode(&blob)?))
    }

    /// Generate and persist device keys for a new scope. Refuses to replace
    /// existing keys: that would silently unlink the device.
    pub async fn create(store: Arc<S>) -> Result<Self, OpsError> {
        if store.load_device_keys().await?.is_some() {
            return Err(OpsError::InvalidInput(
                "scope already has device keys".into(),
            ));
        }
        let keys = DeviceKeys::generate()?;
        store.save_device_keys(&keys.encode()).await?;
        Ok(Self::with_keys(store, keys))
    }

    fn with_keys(store: Arc<S>, keys: DeviceKeys) -> Self {
        Self {
            store,
            keys: RwLock::new(Arc::new(keys)),
            device_write: Mutex::new(()),
            session_lock: Arc::new(Mutex::new(())),
            sender_key_locks: Arc::new(KeyedLocks::default()),
        }
    }

    async fn stores(&self) -> Stores<S> {
        self.stores_over(self.store.clone()).await
    }

    pub(crate) async fn stores_over(&self, store: Arc<S>) -> Stores<S> {
        Stores {
            store,
            keys: self.keys.read().await.clone(),
            sender_key_locks: self.sender_key_locks.clone(),
        }
    }

    pub(crate) fn store(&self) -> &Arc<S> {
        &self.store
    }

    pub(crate) fn session_lock(&self) -> Arc<Mutex<()>> {
        self.session_lock.clone()
    }

    pub(crate) async fn keys(&self) -> Arc<DeviceKeys> {
        self.keys.read().await.clone()
    }

    /// Record this device's own JIDs once the client knows them (after pair
    /// success). Sends need them to build own-device copies.
    pub async fn set_own_jids(&self, pn: &str, lid: Option<&str>) -> Result<(), OpsError> {
        for jid in std::iter::once(pn).chain(lid) {
            jid.parse::<wacore_binary::Jid>()
                .map_err(|_| OpsError::InvalidInput(format!("{jid} is not a JID")))?;
        }
        let _guard = self.device_write.lock().await;
        let mut keys = (**self.keys.read().await).clone();
        keys.own_pn = Some(pn.to_owned());
        keys.own_lid = lid.map(str::to_owned);
        self.replace_keys(keys).await
    }

    async fn replace_keys(&self, keys: DeviceKeys) -> Result<(), OpsError> {
        self.store.save_device_keys(&keys.encode()).await?;
        *self.keys.write().await = Arc::new(keys);
        Ok(())
    }

    pub async fn public_identity(&self) -> PublicIdentity {
        self.keys.read().await.public()
    }

    /// Create `count` one-time prekeys and return their public halves for
    /// upload. The ID counter advances before the keys are written, so a crash
    /// leaves a gap rather than reusing an ID.
    pub async fn generate_prekeys(&self, count: u32) -> Result<Vec<PublicPreKey>, OpsError> {
        if count == 0 || count > 812 {
            // 812 is WhatsApp Web's upload ceiling per request.
            return Err(OpsError::InvalidInput(
                "prekey count must be 1 to 812".into(),
            ));
        }
        let _guard = self.device_write.lock().await;
        let mut keys = (**self.keys.read().await).clone();
        let first = keys.next_prekey_id;
        let mut ids = Vec::with_capacity(count as usize);
        let mut next = first;
        for _ in 0..count {
            ids.push(next);
            next = if next >= MAX_PREKEY_ID { 1 } else { next + 1 };
        }
        keys.next_prekey_id = next;
        self.replace_keys(keys).await?;

        let mut rng = rng();
        let mut records = Vec::with_capacity(ids.len());
        let mut public = Vec::with_capacity(ids.len());
        for id in ids {
            let pair = KeyPair::generate(&mut rng);
            let structure = record_helpers::new_pre_key_record(id, &pair);
            records.push((
                id,
                bytes::Bytes::from(waproto::codec::pre_key_record_to_vec(&structure)),
            ));
            public.push(PublicPreKey {
                id,
                public_key: public_bytes(&pair.public_key),
            });
        }
        self.store.store_prekeys_batch(&records, false).await?;
        Ok(public)
    }

    /// Record that the client uploaded these prekeys. Consumed keys stay gone.
    pub async fn mark_prekeys_uploaded(&self, ids: &[u32]) -> Result<(), OpsError> {
        Ok(self.store.mark_prekeys_uploaded(ids).await?)
    }

    /// Replace the signed prekey. The old one stays loadable by ID so prekey
    /// messages minted against it still decrypt.
    pub async fn rotate_signed_prekey(&self) -> Result<PublicSignedPreKey, OpsError> {
        let _guard = self.device_write.lock().await;
        let mut keys = (**self.keys.read().await).clone();
        let retired = record_helpers::new_signed_pre_key_record(
            keys.signed_prekey_id,
            &keys.signed_prekey,
            keys.signed_prekey_signature,
            wacore::time::now_utc(),
        );
        self.store
            .store_signed_prekey(
                keys.signed_prekey_id,
                &waproto::codec::signed_pre_key_record_to_vec(&retired),
            )
            .await?;
        let pair = KeyPair::generate(&mut rng());
        keys.signed_prekey_signature = sign_prekey(&keys.identity, &pair)?;
        keys.signed_prekey = pair;
        keys.signed_prekey_id = if keys.signed_prekey_id >= MAX_PREKEY_ID {
            1
        } else {
            keys.signed_prekey_id + 1
        };
        let public = keys.public().signed_prekey;
        self.replace_keys(keys).await?;
        Ok(public)
    }

    pub async fn has_session(&self, address: &ProtocolAddress) -> Result<bool, OpsError> {
        Ok(self.store.has_session(address.as_str()).await?)
    }

    /// Run X3DH against a fetched bundle so [`Self::encrypt`] can produce a
    /// `pkmsg` for that device.
    pub async fn establish_session(
        &self,
        address: &ProtocolAddress,
        bundle: &RemoteBundle,
    ) -> Result<(), OpsError> {
        let lock = self.session_lock.clone();
        let _guard = lock.lock().await;
        let staged = Arc::new(self.store.staged());
        self.establish_into(&staged, address, bundle).await?;
        staged.commit().await?;
        Ok(())
    }

    /// X3DH into a staged view without committing it. The caller holds the
    /// session lock and commits.
    pub(crate) async fn establish_into(
        &self,
        staged: &Arc<S>,
        address: &ProtocolAddress,
        bundle: &RemoteBundle,
    ) -> Result<(), OpsError> {
        let bundle = bundle.to_prekey_bundle()?;
        let mut sessions = self.stores_over(staged.clone()).await;
        let mut identities = sessions.clone();
        process_prekey_bundle(
            address,
            &mut sessions,
            &mut identities,
            &bundle,
            &mut rng(),
            UsePQRatchet::No,
        )
        .await?;
        Ok(())
    }

    /// Decrypt one pairwise `<enc>` payload. The session update and the
    /// consumed prekey's removal commit together.
    pub async fn decrypt(
        &self,
        sender: &ProtocolAddress,
        kind: EncKind,
        ciphertext: &[u8],
    ) -> Result<Decrypted, OpsError> {
        let lock = self.session_lock.clone();
        let _guard = lock.lock().await;
        let staged = Arc::new(self.store.staged());
        let decrypted = self.decrypt_into(&staged, sender, kind, ciphertext).await?;
        staged.commit().await?;
        Ok(decrypted)
    }

    /// Decrypt into a staged view without committing it. The caller holds the
    /// address lock and commits.
    pub(crate) async fn decrypt_into(
        &self,
        staged: &Arc<S>,
        sender: &ProtocolAddress,
        kind: EncKind,
        ciphertext: &[u8],
    ) -> Result<Decrypted, OpsError> {
        let mut sessions = self.stores_over(staged.clone()).await;
        let mut identities = sessions.clone();
        let result = match kind {
            EncKind::PreKey => {
                let message = PreKeySignalMessage::try_from(ciphertext)?;
                let mut prekeys = sessions.clone();
                let signed_prekeys = sessions.clone();
                message_decrypt_prekey(
                    &message,
                    sender,
                    &mut sessions,
                    &mut identities,
                    &mut prekeys,
                    &signed_prekeys,
                    &mut rng(),
                    UsePQRatchet::No,
                )
                .await?
            }
            EncKind::Message => {
                let message = SignalMessage::try_from(ciphertext)?;
                message_decrypt_signal(&message, sender, &mut sessions, &mut identities, &mut rng())
                    .await?
            }
        };
        // Staged with the promoted session, so the prekey is never gone while
        // the session that consumed it is not durable.
        if let Some(id) = result.consumed_prekey_id {
            staged.remove_prekey(id.into()).await?;
        }
        Ok(Decrypted {
            plaintext: result.plaintext,
            identity_changed: matches!(
                result.identity_change,
                wacore::libsignal::protocol::IdentityChange::ReplacedExisting
            ),
        })
    }

    /// Encrypt padded plaintext for one device with an existing session.
    pub async fn encrypt(
        &self,
        recipient: &ProtocolAddress,
        plaintext: &[u8],
    ) -> Result<Encrypted, OpsError> {
        let lock = self.session_lock.clone();
        let _guard = lock.lock().await;
        let mut sessions = self.stores().await;
        let mut identities = sessions.clone();
        let message = message_encrypt(plaintext, recipient, &mut sessions, &mut identities).await?;
        let kind = match message.message_type() {
            CiphertextMessageType::PreKey => EncKind::PreKey,
            CiphertextMessageType::Whisper => EncKind::Message,
            other => {
                return Err(OpsError::InvalidInput(format!(
                    "unexpected pairwise ciphertext type {other:?}"
                )));
            }
        };
        Ok(Encrypted {
            kind,
            ciphertext: message.serialize().to_vec(),
        })
    }

    /// The sender-key distribution message for our own chain in `group`,
    /// creating the chain if needed. Encrypt it pairwise to each member device.
    pub async fn sender_key_distribution(
        &self,
        group: &str,
        own_address: &ProtocolAddress,
    ) -> Result<Vec<u8>, OpsError> {
        let name = SenderKeyName::from_parts(group, own_address.as_str());
        let lock = self.session_lock.clone();
        let _guard = lock.lock().await;
        let mut store = self.stores().await;
        let skdm = create_sender_key_distribution_message(&name, &mut store, &mut rng()).await?;
        Ok(skdm.serialized().to_vec())
    }

    /// Encrypt group plaintext (`skmsg`) on our own chain.
    pub async fn group_encrypt(
        &self,
        group: &str,
        own_address: &ProtocolAddress,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OpsError> {
        let name = SenderKeyName::from_parts(group, own_address.as_str());
        let lock = self.session_lock.clone();
        let _guard = lock.lock().await;
        let mut store = self.stores().await;
        let message = group_encrypt(&mut store, &name, plaintext, &mut rng()).await?;
        Ok(message.serialized().to_vec())
    }

    /// Store a member's sender key received in a decrypted message.
    pub async fn process_sender_key_distribution(
        &self,
        group: &str,
        sender: &ProtocolAddress,
        skdm: &[u8],
    ) -> Result<(), OpsError> {
        let name = SenderKeyName::from_parts(group, sender.as_str());
        let message = SenderKeyDistributionMessage::try_from(skdm)?;
        let mut store = self.stores().await;
        process_sender_key_distribution_message(&name, &message, &mut store).await?;
        Ok(())
    }

    /// Decrypt a group `skmsg` into a staged view without committing it.
    pub(crate) async fn group_decrypt_into(
        &self,
        staged: &Arc<S>,
        group: &str,
        sender: &ProtocolAddress,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OpsError> {
        let name = SenderKeyName::from_parts(group, sender.as_str());
        let mut store = self.stores_over(staged.clone()).await;
        Ok(group_decrypt(ciphertext, &mut store, &name).await?)
    }

    /// Store a received sender key in a staged view without committing it.
    pub(crate) async fn process_sender_key_distribution_into(
        &self,
        staged: &Arc<S>,
        group: &str,
        sender: &ProtocolAddress,
        skdm: &[u8],
    ) -> Result<(), OpsError> {
        let name = SenderKeyName::from_parts(group, sender.as_str());
        let message = SenderKeyDistributionMessage::try_from(skdm)?;
        let mut store = self.stores_over(staged.clone()).await;
        process_sender_key_distribution_message(&name, &message, &mut store).await?;
        Ok(())
    }

    /// Decrypt a group `skmsg` from `sender`.
    pub async fn group_decrypt(
        &self,
        group: &str,
        sender: &ProtocolAddress,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OpsError> {
        let name = SenderKeyName::from_parts(group, sender.as_str());
        let lock = self.session_lock.clone();
        let _guard = lock.lock().await;
        let mut store = self.stores().await;
        Ok(group_decrypt(ciphertext, &mut store, &name).await?)
    }

    /// Verify the primary's pair-success container and add our device
    /// signature. Signs only the ADV device-identity message built here, never
    /// caller-chosen bytes.
    pub async fn sign_pairing(
        &self,
        device_identity_container: &[u8],
    ) -> Result<PairingSignature, OpsError> {
        let keys = self.keys.read().await.clone();
        let (signed_identity, key_index) = PairUtils::do_pair_crypto_with(
            &keys.identity,
            &keys.adv_secret,
            device_identity_container,
        )
        .map_err(|e| OpsError::Pairing {
            code: e.code,
            text: e.text,
        })?;
        // Kept for prekey messages, which carry the device identity.
        let _guard = self.device_write.lock().await;
        let mut updated = (**self.keys.read().await).clone();
        updated.account = Some(signed_identity.clone());
        self.replace_keys(updated).await?;
        Ok(PairingSignature {
            signed_identity,
            key_index,
        })
    }
}
