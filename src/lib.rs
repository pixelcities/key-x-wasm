extern crate base64;
extern crate console_error_panic_hook;

use wasm_bindgen::prelude::*;

use std::str;
use std::sync::Arc;
use std::cell::RefCell;
use std::collections::hash_map::HashMap;

use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};

use argon2::{password_hash::{PasswordHasher, SaltString, Output}, Argon2, Params, Algorithm, Version};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use aes_gcm_siv::aead::{Aead, NewAead};

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub struct KeyXInner {
    root_key: Output,
    passphrase: Output,
    keys: RefCell<HashMap<String, String>>
}

#[wasm_bindgen]
pub struct KeyX {
    inner: Arc<KeyXInner>
}

fn gen_nonce<T>(csprng: &mut T) -> [u8; 12] where T: CryptoRng + Rng, {
    let mut nonce = [0u8; 12];
    csprng.fill_bytes(&mut nonce);
    nonce
}

#[wasm_bindgen]
impl KeyX {
    #[wasm_bindgen(constructor)]
    pub fn new(email: String, passphrase: String) -> KeyX {
        console_error_panic_hook::set_once();

        // derive root key
        let root_key = {
            let params = Params::new(4096, 8, 1, Some(32)).unwrap();
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let salt = SaltString::b64_encode(&email.as_bytes()).unwrap();
            argon2.hash_password(passphrase.as_bytes(), &salt).unwrap().hash.unwrap()
        };

        let hashed_passphrase = {
            let params = Params::new(1024, 1, 1, Some(32)).unwrap();
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let salt =  SaltString::b64_encode(&passphrase.as_bytes()).unwrap();
            argon2.hash_password(root_key.as_bytes(), &salt).unwrap().hash.unwrap()
        };

        KeyX { inner: Arc::new(KeyXInner {
            root_key: root_key,
            passphrase: hashed_passphrase,
            keys: RefCell::new(HashMap::new())
        })}
    }

    // Because the root key is based on both the email and passphrase the
    // hash will change when either of the two is mutated. Take care.
    pub fn get_hashed_passphrase(&self) -> String {
        base64::encode(self.inner.passphrase.as_bytes())
    }

    pub fn get_key(&self, id: String) -> String {
        match self.inner.keys.borrow_mut().get(&id) {
            Some(key) => {
                self.decrypt_key(key.clone())
            },
            None => panic!("Invalid key id")
        }
    }

    pub fn encrypt_key(&self, plaintext: String) -> String {
        let mut csprng = OsRng;

        let key = Key::from_slice(self.inner.root_key.as_bytes());
        let cipher = Aes256GcmSiv::new(key);
        let nonce = gen_nonce(&mut csprng);

        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes()).expect("encryption failure!");

        format!("{}:{}", base64::encode(nonce), base64::encode(ciphertext))
    }

    pub fn decrypt_key(&self, ciphertext: String) -> String {
        let split: Vec<&str> = ciphertext.split(':').collect();
        let nonce: Vec<u8> = base64::decode(split[0]).unwrap();
        let bytes = base64::decode(split[1]).unwrap();

        let key = Key::from_slice(self.inner.root_key.as_bytes());
        let cipher = Aes256GcmSiv::new(key);

        let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), bytes.as_ref()).expect("decryption failure!");

        str::from_utf8(&plaintext).unwrap().to_string()
    }
}



#[wasm_bindgen]
pub fn gen_public_key() -> String {
    let mut csprng = OsRng;

    let signed_pre_key_pair = KeyPair::generate(&mut csprng);
    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();

    let pkey = format!("{:X?}", signed_pre_key_public);

    pkey
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_public_key() {
        let _pkey = gen_public_key();

        assert!(true);
    }

    #[test]
    fn test_key_x() {
        let key_x = KeyX::new("hello@pixelcities.io".to_string(), "passphrase".to_string());

        let key = key_x.encrypt_key("secret".to_string());
        let output = "UHx+prKUdklUiBEx:ueoVH1ZUwHV9CAuXGD8GzWZ5KzWcPA==".to_string();
        let decrypted = key_x.decrypt_key(output);

        assert_eq!("secret", decrypted);
    }
}

