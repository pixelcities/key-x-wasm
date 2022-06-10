extern crate base64;
extern crate hex;
extern crate console_error_panic_hook;

use wasm_bindgen::prelude::*;

use std::sync::Arc;
use std::cell::RefCell;
use std::collections::hash_map::HashMap;

use wasm_bindgen_futures::*;
use web_sys::console;
use futures_channel::oneshot;
use js_sys::{Promise};

use rand::rngs::OsRng;
use argon2::{password_hash::{PasswordHasher, SaltString, Output}, Argon2, Params, Algorithm, Version};

use crate::utils::*;
use crate::crypto::*;

pub struct KeyStoreInner {
    root_key: RefCell<Option<Output>>,
    keys: RefCell<HashMap<String, String>>,
    manifest: RefCell<HashMap<String, String>>
}

#[wasm_bindgen]
pub struct KeyStore {
    inner: Arc<KeyStoreInner>
}

#[wasm_bindgen]
impl KeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> KeyStore {
        console_error_panic_hook::set_once();

        KeyStore { inner: Arc::new(KeyStoreInner {
            root_key: RefCell::new(None),
            keys: RefCell::new(HashMap::new()),
            manifest: RefCell::new(HashMap::new())
        })}
    }

    pub fn open_sesame(&self, email: String, passphrase: String) -> String {
        let (root_key, hashed_passphrase) = self.derive_keys(email, passphrase);

        self.inner.root_key.replace(root_key);
        hashed_passphrase
    }

    pub fn get_hashed_passphrase(&self, email: String, passphrase: String) -> String {
        let (_, hashed_passphrase) = self.derive_keys(email, passphrase);

        hashed_passphrase
    }

    pub fn get_named_key(&self, name: String) -> String {
        match self.inner.manifest.borrow().get(&name) {
            Some(entry) => {
                self.get_key(entry.clone())
            },
            None => panic!("No such entry")
        }
    }

    pub fn is_locked(&self) -> bool {
        let root_key = self.inner.root_key.borrow();
        root_key.is_none()
    }

    pub fn init(&self) -> Promise {
        let _self = self.inner.clone();

        let (tx, rx) = oneshot::channel();

        // Get all the keys
        spawn_local(async move {
            let json = request("GET".to_string(), "http://localhost:5000/keys".to_string(), None).await;

            for key in js_sys::try_iter(&json).unwrap().unwrap() {
                let obj = key.unwrap();
                let key_id: String = js_sys::Reflect::get(&obj, &"key_id".into()).unwrap().as_string().unwrap();
                let ciphertext: String = js_sys::Reflect::get(&obj, &"ciphertext".into()).unwrap().as_string().unwrap();

                _self.keys.borrow_mut().insert(key_id, ciphertext);
            }

            // And also the manifest
            spawn_local(async move {
                let json = request("GET".to_string(), "http://localhost:5000/keys/manifest".to_string(), None).await;
                let manifest = js_sys::Reflect::get(&json, &"manifest".into()).unwrap();

                for entry in js_sys::Object::entries(&manifest.into()).iter() {
                    let arr: js_sys::Array = entry.into();

                    let name: String = arr.get(0).as_string().unwrap();
                    let key_id: String = arr.get(1).as_string().unwrap();

                    _self.manifest.borrow_mut().insert(name, key_id);
                }

                drop(tx.send(""));
            });

        });

        let done = async move {
            match rx.await {
                Ok(_) => Ok(JsValue::undefined()),
                Err(_) => Err(JsValue::undefined())
            }
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn get_manifest(&self) -> js_sys::Object {
        let obj = js_sys::Object::new();
        let manifest = self.inner.manifest.borrow().clone();

        for (k, v) in manifest {
            js_sys::Reflect::set(&obj, &k.into(), &v.into()).unwrap();
        }

        obj
    }

    pub fn get_key(&self, id: String) -> String {
        match self.inner.keys.borrow().get(&id) {
            Some(key) => {
                self.decrypt_key(key)
            },
            None => panic!("Invalid key id")
        }
    }

    pub fn create_named_key(&self, name: String, keysize: u32) -> Promise {
        let _self = self.inner.clone();
        let (tx, rx) = oneshot::channel();

        let promise = self.generate_key(keysize);

        spawn_local(async move {
            // Generate a new key
            let key_id = wasm_bindgen_futures::JsFuture::from(promise).await.unwrap().as_string().unwrap();

            // Store it in the local manifest
            _self.manifest.borrow_mut().insert(name, key_id.clone());
            let manifest = _self.manifest.borrow().clone();

            // Sync the manifest
            //
            // First create the body which is simply a json object of name: key_id
            // Next, update the remote manifest
            // We return the key_id, that was generated
            let mut entries = vec![];
            for (k, v) in manifest {
                entries.push(format!("\"{}\": \"{}\"", k, v));
            }

            let body = format!("{{\"manifest\": {{ {} }} }}", entries.join(","));

            request("PUT".to_string(), "http://localhost:5000/keys/manifest".to_string(), Some(body)).await;

            drop(tx.send(key_id));
        });

        let done = async move {
            match rx.await {
                Ok(key_id) => Ok(key_id.into()),
                Err(_) => Err(JsValue::undefined()),
            }
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn add_key(&self, key_id: String, plaintext: String) -> Promise {
        let ciphertext = self.encrypt_key(&plaintext);

        self.inner.keys.borrow_mut().insert(key_id.clone(), ciphertext.clone());

        wasm_bindgen_futures::future_to_promise(async move {
            let body = format!("{{\"ciphertext\": \"{}\"}}", ciphertext);

            request("PUT".to_string(), format!("http://localhost:5000/keys/{}", key_id), Some(body)).await;

            Ok(JsValue::from_str(&key_id))
        })
    }

    pub fn generate_key(&self, keysize: u32) -> Promise {
        let mut csprng = OsRng;

        let _self = self.inner.clone();
        let key = match keysize {
            16 => hex::encode(gen_key_16(&mut csprng)),
            _ => hex::encode(gen_key_32(&mut csprng))
        };
        let ciphertext = self.encrypt_key(&key);

        let (tx, rx) = oneshot::channel();

        spawn_local(async move {
            let body = format!("{{\"ciphertext\": \"{}\"}}", ciphertext);

            let json = request("POST".to_string(), "http://localhost:5000/keys".to_string(), Some(body)).await;

            let key_id: String = js_sys::Reflect::get(&json, &"key_id".into()).unwrap().as_string().unwrap();
            let ciphertext: String = js_sys::Reflect::get(&json, &"ciphertext".into()).unwrap().as_string().unwrap();

            _self.keys.borrow_mut().insert(key_id.clone(), ciphertext);

            drop(tx.send(key_id));
        });

        let done = async move {
            match rx.await {
                Ok(key_id) => Ok(key_id.into()),
                Err(_) => Err(JsValue::undefined()),
            }
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn rotate_keys(&self, email: String, passphrase: String) -> Promise {
        let mut csprng = OsRng;

        console::log_1(&"Rotating keystore".into());

        let (new_root_key, new_hashed_passphrase) = self.derive_keys(email, passphrase);
        let old_keys = self.inner.keys.borrow().clone();
        let token = base64::encode(gen_nonce(&mut csprng));

        let mut batch = vec![];

        for (key_id, ciphertext) in &old_keys {
            let plaintext = self.decrypt_key(ciphertext);
            let new_ciphertext = encrypt_custom(&plaintext, new_root_key.unwrap().as_bytes());

            batch.push(format!("{{\"key_id\": \"{}\", \"ciphertext\": \"{}\"}}", key_id, new_ciphertext));
        }

        let payload = format!("{{\"token\": \"{}\", \"keys\": [{}]}}", token, batch.join(","));

        let (tx, rx) = oneshot::channel();

        spawn_local(async move {
            request("POST".to_string(), "http://localhost:5000/keys/rotate".to_string(), Some(payload)).await;

            drop(tx.send((token, new_hashed_passphrase)));
        });

        let done = async move {
            match rx.await {
                Ok((token, new_hashed_passphrase)) => {
                    let obj = js_sys::Object::new();
                    js_sys::Reflect::set(&obj, &"token".into(), &token.into()).unwrap();
                    js_sys::Reflect::set(&obj, &"hashed_passphrase".into(), &new_hashed_passphrase.into()).unwrap();

                    Ok(obj.into())
                },
                Err(_) => Err(JsValue::undefined()),
            }
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn encrypt_metadata(&self, key_id: String, plaintext: String) -> String {
        let metadata_key = hex::decode(self.get_key(key_id)).unwrap();
        encrypt_custom(&plaintext, &metadata_key[..])
    }

    pub fn decrypt_metadata(&self, key_id: String, ciphertext: String) -> String {
        let metadata_key = hex::decode(self.get_key(key_id)).unwrap();
        decrypt_custom(&ciphertext, &metadata_key[..])
    }

    fn derive_keys(&self, email: String, passphrase: String) -> (Option<Output>, String) {
        // Derive root key
        let root_key = {
            let params = Params::new(4096, 4, 1, Some(32)).unwrap(); // ~ 1250ms
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let salt = SaltString::b64_encode(&email.as_bytes()).unwrap();
            Some(argon2.hash_password(passphrase.as_bytes(), &salt).unwrap().hash.unwrap())
        };

        // Because the root key is based on both the email and passphrase the
        // hash will change when either of the two is mutated. Take care.
        let hashed_passphrase = {
            let params = Params::new(512, 1, 1, Some(32)).unwrap(); // ~ <100ms
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let salt =  SaltString::b64_encode(&passphrase.as_bytes()).unwrap();
            argon2.hash_password(root_key.unwrap().as_bytes(), &salt).unwrap().hash.unwrap()
        };

        (root_key, base64::encode(hashed_passphrase.as_bytes()))
    }

    fn encrypt_key(&self, plaintext: &String) -> String {
        let root_key = self.inner.root_key.borrow().unwrap();
        encrypt_custom(plaintext, root_key.as_bytes())
    }

    fn decrypt_key(&self, ciphertext: &String) -> String {
        let root_key = self.inner.root_key.borrow().unwrap();
        decrypt_custom(ciphertext, root_key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_x() {
        let key_x = KeyStore::new();
        key_x.open_sesame("hello@pixelcities.io".to_string(), "passphrase".to_string());

        let key = key_x.encrypt_key(&"secret".to_string());
        let output = "Bas52beOECLMh+sr:ER+eJfhHdtE6qkUhrDlVfeiOqkoevw==".to_string();
        let decrypted = key_x.decrypt_key(&output);

        assert_eq!("secret", decrypted);
    }
}

