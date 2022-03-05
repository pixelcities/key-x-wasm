extern crate base64;
extern crate console_error_panic_hook;

use wasm_bindgen::prelude::*;
use js_sys::{Promise, Date};

use std::sync::Arc;
use std::cell::RefCell;
use std::convert::TryFrom;

use rand::rngs::OsRng;
use libsignal_protocol::*;
use libsignal_protocol::{PreKeyBundle, PreKeySignalMessage};
use crate::storage::{SyncableStore, PreKeyBundleSerde};


pub struct ProtocolInner {
    storage: RefCell<Option<SyncableStore>>
}

#[wasm_bindgen]
pub struct Protocol {
    inner: Arc<ProtocolInner>
}

async fn gen_pre_key_bundles(storage: &mut SyncableStore) -> String {
    let mut csprng = OsRng;

    // TODO: allow multiple
    let signed_pre_key_id = 1;
    let signed_pre_key_pair = KeyPair::generate(&mut csprng);

    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = storage.store
        .get_identity_key_pair(None).await.unwrap()
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut csprng).unwrap();

    let pre_key_id = 1;
    let pre_key_pair = KeyPair::generate(&mut csprng);

    storage.store.save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &pre_key_pair), None).await.unwrap();
    storage.store.save_signed_pre_key(
        signed_pre_key_id,
        &SignedPreKeyRecord::new(
            signed_pre_key_id,
            Date::now() as u64,
            &signed_pre_key_pair,
            &signed_pre_key_signature,
        ),
        None
    ).await.unwrap();

    // TODO: send to server

    let pre_key_bundle: PreKeyBundleSerde = PreKeyBundle::new(
        storage.store.get_local_registration_id(None).await.unwrap(),
        1,
        Some((pre_key_id, pre_key_pair.public_key)),
        signed_pre_key_id,
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        *storage.store.get_identity_key_pair(None).await.unwrap().identity_key(),
    ).unwrap().into();
    let payload = base64::encode(pre_key_bundle.serialize());

    payload
}

#[wasm_bindgen]
impl Protocol {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Protocol {
        console_error_panic_hook::set_once();

        Protocol {
            inner: Arc::new(ProtocolInner {
                storage: RefCell::new(None)
            })
        }
    }

    pub fn init(&self, secret_key: String) -> Promise {
        let _self = self.inner.clone();

        let done = async move {
            let storage = SyncableStore::new(secret_key).await;

            _self.storage.replace(Some(storage));

            Ok(JsValue::undefined())
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn register(&self, secret_key: String) -> Promise {
        let _self = self.inner.clone();

        let done = async move {
            let mut storage = SyncableStore::register(secret_key);
            let pre_key_bundle = gen_pre_key_bundles(&mut storage).await;
            _self.storage.replace(Some(storage));

            Ok(JsValue::from_str(&pre_key_bundle))
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn load_prekey_bundle(&self, user_id: String, bundle: String) -> Promise {
        let mut csprng = OsRng;

        let _self = self.inner.clone();
        let done = async move {
            let mut storage = _self.storage.borrow_mut().take().unwrap();

            let address = ProtocolAddress::new(user_id, 1);
            let pre_key_bundle: PreKeyBundle = PreKeyBundleSerde::deserialize(&base64::decode(&bundle).unwrap()[..]).into();

            process_prekey_bundle(
                &address,
                &mut storage.store.session_store,
                &mut storage.store.identity_store,
                &pre_key_bundle,
                &mut csprng,
                None,
            ).await.unwrap();

            _self.storage.replace(Some(storage));

            Ok(JsValue::undefined())
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn encrypt(&self, user_id: String, message: String) -> Promise {
        let address = ProtocolAddress::new(user_id, 1);

        let _self = self.inner.clone();
        let done = async move {
            let mut storage = _self.storage.borrow_mut().take().unwrap();

            let encrypted = message_encrypt(message.as_bytes(), &address, &mut storage.store.session_store, &mut storage.store.identity_store, None).await.unwrap();

            _self.storage.replace(Some(storage));

            Ok(JsValue::from_str(&base64::encode(&encrypted.serialize())))
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn decrypt(&self, user_id: String, message: String) -> Promise {
        let mut csprng = OsRng;
        let address = ProtocolAddress::new(user_id, 1);

        let _self = self.inner.clone();
        let done = async move {
            let mut storage = _self.storage.borrow_mut().take().unwrap();

            let bytes = base64::decode(&message).unwrap();

            // TODO: check message type
            let ctext = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(&bytes[..]).unwrap()
            );

            let decrypted = message_decrypt(
                &ctext,
                &address,
                &mut storage.store.session_store,
                &mut storage.store.identity_store,
                &mut storage.store.pre_key_store,
                &mut storage.store.signed_pre_key_store,
                &mut csprng,
                None,
            ).await.unwrap();

            _self.storage.replace(Some(storage));

            Ok(JsValue::from_str(&String::from_utf8(decrypted).unwrap()))
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn sync(&self) -> Promise {
        let store = self.inner.storage.borrow().clone().unwrap();

        let done = async move {
            store.sync().await;

            Ok(JsValue::undefined())
        };

        wasm_bindgen_futures::future_to_promise(done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol() {
        let protocol = Protocol::new();

        assert!(true);
    }
}

