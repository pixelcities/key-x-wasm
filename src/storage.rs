extern crate base64;

use std::collections::HashMap;
use std::borrow::Cow;

use rand::rngs::OsRng;
use libsignal_protocol::*;
use libsignal_protocol::SessionStore;
use uuid::Uuid;

use serde::{Deserialize, Serialize};

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

pub struct SyncableStore {
    #[allow(dead_code)]
    pub store: InMemSignalProtocolStore
}

fn load_state(_secret_key: &String) -> InMemSignalProtocolStore {
    // TODO: actually load state
    let mut csprng = OsRng;
    let identity_key = IdentityKeyPair::generate(&mut csprng);

    InMemSignalProtocolStore::new(identity_key, 1).unwrap()
}

impl SyncableStore {
    pub fn new(secret_key: &String) -> SyncableStore {
        let store = load_state(secret_key);

        SyncableStore {
            store: store
        }
    }

    pub fn register() -> SyncableStore {
        let mut csprng = OsRng;
        let identity_key = IdentityKeyPair::generate(&mut csprng);
        let store = InMemSignalProtocolStore::new(identity_key, 1).unwrap();

        SyncableStore {
            store: store
        }
    }

    #[allow(dead_code)]
    pub async fn deserialize(data: &[u8]) -> Self {
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

        Self {
            store: store
        }
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
}


#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::IdentityKeyStore;
    use futures_util::FutureExt;

    #[test]
    fn test_serde() {
        async {
            let mut store = SyncableStore::register();
            let key_pair = store.store.get_identity_key_pair(None).await.unwrap();
            let identity_key = key_pair.identity_key();

            let encoded = base64::encode(store.serialize());
            let bytes = &base64::decode(encoded).unwrap();

            let store = SyncableStore::deserialize(bytes).await;
            let key_pair = store.store.get_identity_key_pair(None).await.unwrap();
            let roundtrip_identity_key = key_pair.identity_key();

            assert_eq!(identity_key, roundtrip_identity_key);
        }
        .now_or_never()
        .expect("sync")
    }
}

