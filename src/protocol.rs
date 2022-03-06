extern crate base64;
extern crate console_error_panic_hook;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use js_sys::{Promise, Date};
use web_sys::console;

use std::sync::Arc;
use std::cell::RefCell;
use std::convert::TryFrom;

use rand::rngs::OsRng;
use libsignal_protocol::*;
use libsignal_protocol::{PreKeyBundle, PreKeySignalMessage};
use crate::storage::{SyncableStore, PreKeyBundleSerde};

use crate::utils::*;

pub struct ProtocolInner {
    storage: RefCell<Option<SyncableStore>>
}

#[wasm_bindgen]
pub struct Protocol {
    inner: Arc<ProtocolInner>
}

async fn gen_pre_key_bundles(storage: &mut SyncableStore) -> () {
    let mut csprng = OsRng;

    // TODO: allow multiple
    let signed_pre_key_id = 1;
    let signed_pre_key_pair = KeyPair::generate(&mut csprng);

    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = storage.store
        .get_identity_key_pair(None).await.unwrap()
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut csprng).unwrap();

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

    let identity_key = *storage.store.get_identity_key_pair(None).await.unwrap().identity_key();

    for i in 1..6 {
        let pre_key_id = i;
        let pre_key_pair = KeyPair::generate(&mut csprng);

        storage.store.save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &pre_key_pair), None).await.unwrap();

        let pre_key_bundle: PreKeyBundleSerde = PreKeyBundle::new(
            storage.store.get_local_registration_id(None).await.unwrap(),
            1,
            Some((pre_key_id, pre_key_pair.public_key)),
            signed_pre_key_id,
            signed_pre_key_pair.public_key,
            signed_pre_key_signature.to_vec(),
            identity_key,
        ).unwrap().into();
        let bundle = base64::encode(pre_key_bundle.serialize());
        let payload = format!("{{\"bundle_id\": {}, \"bundle\": \"{}\" }}", pre_key_id, bundle);

        request("POST".to_string(), "http://localhost:5000/protocol/bundles".to_owned(), Some(payload)).await;
    };
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

            // Generate and publish some bundles
            gen_pre_key_bundles(&mut storage).await;

            // Share our identity public key
            let identity_key = base64::encode(storage.store.identity_store.get_identity_key_pair(None).await.unwrap().public_key().serialize());

            // Save state
            storage.sync().await;

            _self.storage.replace(Some(storage));

            Ok(JsValue::from_str(&identity_key))
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn encrypt(&self, user_id: String, message: String) -> Promise {
        let mut csprng = OsRng;
        let address = ProtocolAddress::new(user_id.clone(), 1);

        let _self = self.inner.clone();
        let done = async move {
            let mut storage = _self.storage.borrow_mut().take().unwrap();

            // No existing session means we need to fetch a pre_key_bundle
            if storage.store.session_store.load_session(&address, None).await.unwrap().is_none() {
                let response = request("GET".to_string(), format!("http://localhost:5000/protocol/bundles/{}", &user_id), None).await; // assume it has a bundle
                let bundle_id = response.as_f64().unwrap() as u32;

                let bundle = request("DELETE".to_string(), format!("http://localhost:5000/protocol/bundles/{}/{}", &user_id, &bundle_id), None).await.as_string().unwrap();
                let pre_key_bundle: PreKeyBundle = PreKeyBundleSerde::deserialize(&base64::decode(&bundle).unwrap()[..]).into();

                // Create the session
                process_prekey_bundle(
                    &address,
                    &mut storage.store.session_store,
                    &mut storage.store.identity_store,
                    &pre_key_bundle,
                    &mut csprng,
                    None,
                ).await.unwrap();
            }

            let encrypted = message_encrypt(message.as_bytes(), &address, &mut storage.store.session_store, &mut storage.store.identity_store, None).await.unwrap();

            _self.storage.replace(Some(storage));

            Ok(JsValue::from_str(&base64::encode(&encrypted.serialize())))
        };

        self.schedule_sync();

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn decrypt(&self, user_id: String, message: String) -> Promise {
        let mut csprng = OsRng;
        let address = ProtocolAddress::new(user_id.clone(), 1);

        let _self = self.inner.clone();
        let done = async move {
            let mut storage = _self.storage.borrow_mut().take().unwrap();

            let session_exists = storage.store.session_store.load_session(&address, None).await.unwrap();

            let bytes = base64::decode(&message).unwrap();
            let ctext = match session_exists {
                Some(_) => {
                    // Prekey messages may be queued up, maybe fallback to prekey type
                    match SignalMessage::try_from(&bytes[..]) {
                        Ok(message) => CiphertextMessage::SignalMessage(message),
                        Err(_) => CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(&bytes[..]).unwrap())
                    }
                },
                None => CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(&bytes[..]).unwrap()),
            };

            let maybe_decrypted = message_decrypt(
                &ctext,
                &address,
                &mut storage.store.session_store,
                &mut storage.store.identity_store,
                &mut storage.store.pre_key_store,
                &mut storage.store.signed_pre_key_store,
                &mut csprng,
                None,
            ).await;

            _self.storage.replace(Some(storage));

            match maybe_decrypted {
                Ok(decrypted) => {
                    Ok(JsValue::from_str(&String::from_utf8(decrypted).unwrap()))
                },
                Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                    Err(JsValue::from_str(&"DuplicatedMessageError".to_owned()))
                },
                Err(e) => {
                    console::log_2(&"Error when decrypting message: ".into(), &e.to_string().into());
                    Err(JsValue::from_str(&"MessageDecryptError".to_owned()))
                }
            }
        };

        self.schedule_sync();

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn sync(&self) -> Promise {
        let store = self.inner.storage.borrow().clone().unwrap();

        wasm_bindgen_futures::future_to_promise(async move {
            store.sync().await;

            Ok(JsValue::undefined())
        })
    }

    pub fn schedule_sync(&self) -> () {
        let window = web_sys::window().unwrap();

        let _self = self.inner.clone();
        let f = Closure::wrap(Box::new(move || {
            let storage = _self.storage.borrow().clone().unwrap();

            let _obj: &js_sys::Object = wasm_bindgen_futures::future_to_promise(async move {
                storage.sync().await;

                Ok(JsValue::undefined())
            }).as_ref();

        }) as Box<dyn FnMut()>);
        window.set_timeout_with_callback_and_timeout_and_arguments_0(&f.as_ref().unchecked_ref(), 30_000).unwrap();

        // TODO: this leaks memory
        f.forget();
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

