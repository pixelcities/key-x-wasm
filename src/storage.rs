extern crate base64;
extern crate hex;

use std::collections::HashMap;
use std::borrow::Cow;

use rand::rngs::OsRng;
use libsignal_protocol::*;
use libsignal_protocol::SessionStore;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

use crate::utils::*;
use crate::crypto::*;

/*
 * Simply (and unsafely) override some internal structs to enable
 * serialization of the private hashmaps.
 *
 * This is terrible, but much quicker than implementing the storage
 * traits. Not every operation needs hit the remote server (immediately)
 * anyways, as we can just sync it at intervals so that frequent mutations
 * are buffered.
 *
 * TODO: Impl src/storage/traits.rs
 */
#[allow(dead_code)]
pub struct PubSessionStore {
    pub sessions: HashMap<ProtocolAddress, SessionRecord>,
}

#[allow(dead_code)]
type PreKeyId = u32;

#[allow(dead_code)]
pub struct PubPreKeyStore {
    pub pre_keys: HashMap<PreKeyId, PreKeyRecord>,
}

#[allow(dead_code)]
type SignedPreKeyId = u32;

#[allow(dead_code)]
pub struct PubSignedPreKeyStore {
    pub signed_pre_keys: HashMap<SignedPreKeyId, SignedPreKeyRecord>,
}

#[allow(dead_code)]
struct PubIdentityKeyStore {
    pub key_pair: IdentityKeyPair,
    pub id: u32,
    pub known_keys: HashMap<ProtocolAddress, IdentityKey>,
}

#[allow(dead_code)]
pub struct PubSenderKeyStore {
    pub keys: HashMap<(Cow<'static, ProtocolAddress>, Uuid), SenderKeyRecord>,
}


#[derive(Clone, Deserialize, Serialize)]
struct State {
    sessions: Vec<((String, u32), Vec<u8>)>, // HashMap<ProtocolAddress, SessionRecord>
    pre_keys: Vec<(u32, Vec<u8>)>, // HashMap<PreKeyId, PreKeyRecord>
    signed_pre_keys: Vec<(u32, Vec<u8>)>, // HashMap<SignedPreKeyId, SignedPreKeyRecord>
    key_pair: (Vec<u8>, Vec<u8>), // IdentityKeyPair
    id: u32, // registration_id (not used)
    known_keys: Vec<((String, u32), Vec<u8>)>, // HashMap<ProtocolAddress, IdentityKey>
    keys: Vec<(((String, u32), String), Vec<u8>)>, // HashMap<(Cow<'static, ProtocolAddress>, Uuid), SenderKeyRecord>
}

#[derive(Clone)]
pub struct SyncableStore {
    #[allow(dead_code)]
    pub store: InMemSignalProtocolStore,
    #[allow(dead_code)]
    secret_key: Vec<u8>
}

/*
 * Syncable ProtocolStore
 *
 * Wrapper around the ProtocolStore, with some added functions to enable syncing the store
 * remotely. This implementation is not exactly safe from race conditions, as it may be killed
 * at any time before syncing the state. Rather than doing this properly we will just take the
 * easy road for now and embrace this property by only syncing sporadically to keep the overhead
 * low.
 *
 * This does require that any messages in limbo (or just all of them) need to be replayed.
 */
impl SyncableStore {
    pub fn register(secret_key: String) -> SyncableStore {
        let mut csprng = OsRng;
        let identity_key = IdentityKeyPair::generate(&mut csprng);
        let store = InMemSignalProtocolStore::new(identity_key, 1).unwrap();

        SyncableStore {
            store: store,
            secret_key: hex::decode(secret_key).unwrap()
        }
    }

    pub async fn new(secret_key: String) -> Self {
        let json = request("GET".to_string(), format!("{}/protocol/sync", env!("API_BASEPATH")), None).await;

        let secret = hex::decode(secret_key).unwrap();
        let cstate: String = js_sys::Reflect::get(&json, &"state".into()).unwrap().as_string().unwrap();
        let bytes = base64::decode(decrypt_custom(&cstate, &secret[..]).unwrap()).unwrap();

        let store = SyncableStore::deserialize(&bytes[..]).await;

        SyncableStore {
            store: store,
            secret_key: secret
        }
    }

    #[allow(dead_code)]
    pub async fn deserialize(data: &[u8]) -> InMemSignalProtocolStore {
        let state: State = bincode::deserialize(data).unwrap();

        // Start with the identity_key, so that the store may be initialized
        let public_key = IdentityKey::new(PublicKey::deserialize(&state.key_pair.0[..]).unwrap());
        let private_key = PrivateKey::deserialize(&state.key_pair.1[..]).unwrap();
        let identity_key = IdentityKeyPair::new(public_key, private_key);

        let mut store = InMemSignalProtocolStore::new(identity_key, 1).unwrap();

        for (k, v) in state.sessions {
            let address = ProtocolAddress::new(k.0, k.1);
            let record = SessionRecord::deserialize(&v[..]).unwrap();

            store.store_session(&address, &record, None).await.unwrap();
        }

        for (k, v) in state.pre_keys {
            let id: PreKeyId = k;
            let record = PreKeyRecord::deserialize(&v[..]).unwrap();

            store.save_pre_key(id, &record, None).await.unwrap();
        }

        for (k, v) in state.signed_pre_keys {
            let id: PreKeyId = k;
            let record = SignedPreKeyRecord::deserialize(&v[..]).unwrap();

            store.save_signed_pre_key(id, &record, None).await.unwrap();
        }

        for (k, v) in state.known_keys {
            let address = ProtocolAddress::new(k.0, k.1);
            let key = IdentityKey::new(PublicKey::deserialize(&v[..]).unwrap());

            store.save_identity(&address, &key, None).await.unwrap();
        }

        for (k, v) in state.keys {
            let address = ProtocolAddress::new(k.0.0, k.0.1);
            let uuid = Uuid::parse_str(&k.1).unwrap();
            let record = SenderKeyRecord::deserialize(&v[..]).unwrap();

            store.store_sender_key(&address, uuid, &record, None).await.unwrap();
        }

        store
    }

    #[allow(dead_code)]
    pub fn serialize(&self) -> Vec<u8> {
        let session_store: PubSessionStore = unsafe { std::mem::transmute(self.store.session_store.clone()) };
        let sessions = session_store.sessions.into_iter().map(|(k,v)| ((k.name().to_string(), k.device_id()), v.serialize().unwrap()) ).collect();

        let pre_key_store: PubPreKeyStore = unsafe { std::mem::transmute(self.store.pre_key_store.clone()) };
        let pre_keys = pre_key_store.pre_keys.into_iter().map(|(k,v)| (k, v.serialize().unwrap()) ).collect();

        let signed_pre_key_store: PubSignedPreKeyStore = unsafe { std::mem::transmute(self.store.signed_pre_key_store.clone()) };
        let signed_pre_keys = signed_pre_key_store.signed_pre_keys.into_iter().map(|(k,v)| (k, v.serialize().unwrap()) ).collect();

        let identity_store: PubIdentityKeyStore = unsafe { std::mem::transmute(self.store.identity_store.clone()) };
        let identity_key = identity_store.key_pair.identity_key().public_key().serialize();
        let private_key = identity_store.key_pair.private_key().serialize();
        let id = identity_store.id;
        let known_keys = identity_store.known_keys.into_iter().map(|(k,v)| ((k.name().to_string(), k.device_id()), v.public_key().serialize().to_vec()) ).collect();

        let sender_key_store: PubSenderKeyStore = unsafe { std::mem::transmute(self.store.sender_key_store.clone()) };
        let keys = sender_key_store.keys.into_iter().map(|(k,v)| (((k.0.name().to_string(), k.0.device_id()), k.1.to_string()), v.serialize().unwrap()) ).collect();

        let state = State {
            sessions: sessions,
            pre_keys: pre_keys,
            signed_pre_keys: signed_pre_keys,
            key_pair: (identity_key.to_vec(), private_key),
            id: id,
            known_keys: known_keys,
            keys: keys
        };

        bincode::serialize(&state).unwrap()
    }

    /*
     * Save the current state remotely
     *
     * While this is never truly in sync, we can replay (incoming AND outgoing) messages after
     * the state is restored to get all the chains back in order. This assumes that we don't
     * lose messages and are willing to replay a ton of them.
     */
    pub async fn sync(&self) -> () {
        let bytes = self.serialize();
        let cstate = encrypt_custom(&base64::encode(&bytes), &self.secret_key[..]);
        let payload = format!("{{\"state\": \"{}\" }}", cstate);

        request("PUT".to_string(), format!("{}/protocol/sync", env!("API_BASEPATH")), Some(payload)).await;
    }
}


#[derive(Clone, Deserialize, Serialize)]
pub struct PreKeyBundleSerde {
    registration_id: u32, // registration_id: u32,
    device_id: u32, // device_id: u32,
    pre_key_id: Option<u32>, // pre_key_id: Option<PreKeyId>,
    pre_key_public: Vec<u8>, // pre_key_public: Option<PublicKey>,
    signed_pre_key_id: u32, // signed_pre_key_id: SignedPreKeyId,
    signed_pre_key_public: Vec<u8>, // signed_pre_key_public: PublicKey,
    signed_pre_key_signature: Vec<u8>, // signed_pre_key_signature: Vec<u8>,
    identity_key: Vec<u8> // identity_key: IdentityKey,
}

impl PreKeyBundleSerde {
    pub fn deserialize(data: &[u8]) -> Self {
        bincode::deserialize(data).unwrap()
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}

impl From<PreKeyBundle> for PreKeyBundleSerde {
    fn from(bundle: PreKeyBundle) -> Self {
        PreKeyBundleSerde {
            registration_id: bundle.registration_id().unwrap(),
            device_id: bundle.device_id().unwrap(),
            pre_key_id: bundle.pre_key_id().unwrap(),
            pre_key_public: bundle.pre_key_public().unwrap().unwrap().serialize().to_vec(),
            signed_pre_key_id: bundle.signed_pre_key_id().unwrap(),
            signed_pre_key_public: bundle.signed_pre_key_public().unwrap().serialize().to_vec(),
            signed_pre_key_signature: bundle.signed_pre_key_signature().unwrap().to_vec(),
            identity_key: bundle.identity_key().unwrap().public_key().serialize().to_vec(),
        }
    }
}

impl From<PreKeyBundleSerde> for PreKeyBundle {
    fn from(bundle: PreKeyBundleSerde) -> Self {
        PreKeyBundle::new(
            bundle.registration_id,
            bundle.device_id,
            Some((bundle.pre_key_id.unwrap(), PublicKey::deserialize(&bundle.pre_key_public).unwrap())),
            bundle.signed_pre_key_id,
            PublicKey::deserialize(&bundle.signed_pre_key_public).unwrap(),
            bundle.signed_pre_key_signature,
            IdentityKey::new(PublicKey::deserialize(&bundle.identity_key).unwrap()),
        ).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::IdentityKeyStore;
    use futures_util::FutureExt;

    #[test]
    fn test_serde() {
        async {
            let mut storage: SyncableStore = SyncableStore::register("".to_owned());
            let key_pair = &storage.store.get_identity_key_pair(None).await.unwrap();
            let identity_key = key_pair.identity_key();

            let encoded = base64::encode(storage.serialize());
            let bytes = &base64::decode(encoded).unwrap();

            let store = SyncableStore::deserialize(bytes).await;
            let key_pair = store.get_identity_key_pair(None).await.unwrap();
            let roundtrip_identity_key = key_pair.identity_key();

            assert_eq!(identity_key, roundtrip_identity_key);
        }
        .now_or_never()
        .expect("sync")
    }
}

