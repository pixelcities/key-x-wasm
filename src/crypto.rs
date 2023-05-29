extern crate hex;

use wasm_bindgen::prelude::*;
use std::str;

use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv, Key as AesKey, Nonce};
use aes_gcm_siv::aead::{Aead, NewAead};

pub fn gen_nonce<T>(csprng: &mut T) -> [u8; 12] where T: CryptoRng + Rng, {
    let mut nonce = [0u8; 12];
    csprng.fill_bytes(&mut nonce);
    nonce
}

pub fn gen_key_16<T>(csprng: &mut T) -> [u8; 16] where T: CryptoRng + Rng, {
    let mut key = [0u8; 16];
    csprng.fill_bytes(&mut key);
    key
}

pub fn gen_key_32<T>(csprng: &mut T) -> [u8; 32] where T: CryptoRng + Rng, {
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    key
}

pub fn encrypt_custom(plaintext: &String, secret_key: &[u8]) -> String {
    let mut csprng = OsRng;

    let nonce = gen_nonce(&mut csprng);

    let ciphertext = if secret_key.len() == 16 {
        let key = AesKey::from_slice(secret_key);
        let cipher = Aes128GcmSiv::new(key);
        cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes()).expect("encryption failure!")

    } else {
        let key = AesKey::from_slice(secret_key);
        let cipher = Aes256GcmSiv::new(key);
        cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes()).expect("encryption failure!")
    };

    format!("{}:{}", base64::encode(nonce), base64::encode(ciphertext))
}

pub fn decrypt_custom(ciphertext: &String, secret_key: &[u8]) -> Result<String, String> {
    let split: Vec<&str> = ciphertext.split(':').collect();
    let nonce: Vec<u8> = base64::decode(split[0]).unwrap();
    let bytes = base64::decode(split[1]).unwrap();

    if secret_key.len() == 16 {
        let key = AesKey::from_slice(secret_key);
        let cipher = Aes128GcmSiv::new(key);

        match cipher.decrypt(Nonce::from_slice(&nonce), bytes.as_ref()) {
            Ok(plaintext) => Ok(str::from_utf8(&plaintext).unwrap().to_string()),
            Err(_) => Err("decryption failure!".to_string())
        }

    } else {
        let key = AesKey::from_slice(secret_key);
        let cipher = Aes256GcmSiv::new(key);

        match cipher.decrypt(Nonce::from_slice(&nonce), bytes.as_ref()) {
            Ok(plaintext) => Ok(str::from_utf8(&plaintext).unwrap().to_string()),
            Err(_) => Err("decryption failure!".to_string())
        }
    }
}

#[wasm_bindgen]
pub fn aes_gcm_siv_encrypt(plaintext: String, secret_key: String) -> String {
    encrypt_custom(&plaintext, &hex::decode(secret_key).unwrap())
}

#[wasm_bindgen]
pub fn aes_gcm_siv_decrypt(ciphertext: String, secret_key: String) -> String {
    decrypt_custom(&ciphertext, &hex::decode(secret_key).unwrap()).unwrap()
}
