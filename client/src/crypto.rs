use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use shared::{EncryptedChatMessage, PlaintextChatMessage};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const MESSAGE_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const XCHACHA20_KEY_LEN: usize = 32;
const KEY_DERIVATION_SALT: &[u8] = b"phantasma x25519 xchacha20poly1305 v1";

pub fn encrypt_message(
    sender: &str,
    recipient: &str,
    body: &str,
    sender_secret_key: &[u8; 32],
    sender_public_key: &str,
    recipient_public_key: &str,
) -> anyhow::Result<EncryptedChatMessage> {
    let sender_public_key_bytes = decode_fixed_key(sender_public_key, "sender public key")?;
    let recipient_public_key_bytes =
        decode_fixed_key(recipient_public_key, "recipient public key")?;
    let sender_secret = StaticSecret::from(*sender_secret_key);
    let recipient_public = X25519PublicKey::from(recipient_public_key_bytes);
    let shared_secret = sender_secret.diffie_hellman(&recipient_public);
    let message_key = derive_message_key(
        shared_secret.as_bytes(),
        &sender_public_key_bytes,
        &recipient_public_key_bytes,
    )?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let plaintext = PlaintextChatMessage::new(sender, recipient, body).to_wire_bytes()?;
    let associated_data = associated_data(&sender_public_key_bytes, &recipient_public_key_bytes);
    let cipher = XChaCha20Poly1305::new((&message_key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &associated_data,
            },
        )
        .map_err(|_| anyhow::anyhow!("message encryption failed"))?;

    Ok(EncryptedChatMessage {
        version: MESSAGE_VERSION,
        sender_encryption_public_key: sender_public_key.to_string(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt_message(
    recipient_secret_key: &[u8; 32],
    recipient_public_key: &str,
    encrypted: &EncryptedChatMessage,
) -> anyhow::Result<PlaintextChatMessage> {
    if encrypted.version != MESSAGE_VERSION {
        bail!("unsupported encrypted message version");
    }

    let sender_public_key_bytes =
        decode_fixed_key(&encrypted.sender_encryption_public_key, "sender public key")?;
    let recipient_public_key_bytes =
        decode_fixed_key(recipient_public_key, "recipient public key")?;
    let nonce = decode_nonce(&encrypted.nonce)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .context("ciphertext is not valid base64url")?;
    let recipient_secret = StaticSecret::from(*recipient_secret_key);
    let sender_public = X25519PublicKey::from(sender_public_key_bytes);
    let shared_secret = recipient_secret.diffie_hellman(&sender_public);
    let message_key = derive_message_key(
        shared_secret.as_bytes(),
        &sender_public_key_bytes,
        &recipient_public_key_bytes,
    )?;
    let associated_data = associated_data(&sender_public_key_bytes, &recipient_public_key_bytes);
    let cipher = XChaCha20Poly1305::new((&message_key).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &associated_data,
            },
        )
        .map_err(|_| anyhow::anyhow!("message decryption failed"))?;

    Ok(PlaintextChatMessage::from_wire_bytes(&plaintext)?)
}

fn derive_message_key(
    shared_secret: &[u8; 32],
    sender_public_key: &[u8; 32],
    recipient_public_key: &[u8; 32],
) -> anyhow::Result<[u8; XCHACHA20_KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(Some(KEY_DERIVATION_SALT), shared_secret);
    let info = associated_data(sender_public_key, recipient_public_key);
    let mut key = [0u8; XCHACHA20_KEY_LEN];

    hkdf.expand(&info, &mut key)
        .map_err(|_| anyhow::anyhow!("message key derivation failed"))?;

    Ok(key)
}

fn associated_data(sender_public_key: &[u8; 32], recipient_public_key: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(13 + sender_public_key.len() + recipient_public_key.len());

    data.extend_from_slice(b"phantasma:v1:");
    data.extend_from_slice(sender_public_key);
    data.extend_from_slice(recipient_public_key);

    data
}

fn decode_fixed_key(encoded: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .with_context(|| format!("{label} is not valid base64url"))?;

    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be 32 bytes"))
}

fn decode_nonce(encoded: &str) -> anyhow::Result<[u8; NONCE_LEN]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("nonce is not valid base64url")?;

    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce must be {NONCE_LEN} bytes"))
}

#[cfg(test)]
mod tests {
    use super::{decrypt_message, encrypt_message};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    struct TestIdentity {
        secret_key: [u8; 32],
        public_key: String,
    }

    fn test_identity() -> TestIdentity {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);

        TestIdentity {
            secret_key: secret.to_bytes(),
            public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        }
    }

    #[test]
    fn encrypted_message_decrypts_for_recipient_and_fails_for_someone_else() {
        let alice = test_identity();
        let bob = test_identity();
        let charlie = test_identity();

        let encrypted = encrypt_message(
            "alice",
            "bob",
            "hello bob",
            &alice.secret_key,
            &alice.public_key,
            &bob.public_key,
        )
        .expect("message should encrypt");
        let decrypted = decrypt_message(&bob.secret_key, &bob.public_key, &encrypted)
            .expect("bob should decrypt");
        let wrong_recipient = decrypt_message(&charlie.secret_key, &charlie.public_key, &encrypted);

        assert_eq!(decrypted.from, "alice");
        assert_eq!(decrypted.to, "bob");
        assert_eq!(decrypted.body, "hello bob");
        assert!(wrong_recipient.is_err());
    }
}
