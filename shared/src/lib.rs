use serde::{Deserialize, Serialize};

pub const ED25519_PUBLIC_KEY_TEXT_LEN: usize = 43;
pub const X25519_PUBLIC_KEY_TEXT_LEN: usize = 43;
pub const MAX_USERNAME_LEN: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlaintextChatMessage {
    pub from: String,
    pub to: String,
    pub body: String,
}

impl PlaintextChatMessage {
    pub fn new(from: impl Into<String>, to: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            body: body.into(),
        }
    }

    pub fn to_wire_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedChatMessage {
    pub version: u8,
    pub sender_encryption_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl EncryptedChatMessage {
    pub fn to_wire_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutedEncryptedMessage {
    pub from: String,
    pub to: String,
    pub encrypted: EncryptedChatMessage,
}

impl RoutedEncryptedMessage {
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        encrypted: EncryptedChatMessage,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            encrypted,
        }
    }

    pub fn to_wire_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKeyRegistration {
    pub username: String,
    pub identity_public_key: String,
    pub encryption_public_key: String,
}

impl PublicKeyRegistration {
    pub fn new(
        username: impl Into<String>,
        identity_public_key: impl Into<String>,
        encryption_public_key: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            identity_public_key: identity_public_key.into(),
            encryption_public_key: encryption_public_key.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKeyEntry {
    pub username: String,
    pub identity_public_key: String,
    pub encryption_public_key: String,
}

pub fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= MAX_USERNAME_LEN
        && username
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
}

pub fn is_valid_ed25519_public_key_text(public_key: &str) -> bool {
    public_key.len() == ED25519_PUBLIC_KEY_TEXT_LEN
        && public_key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

pub fn is_valid_x25519_public_key_text(public_key: &str) -> bool {
    public_key.len() == X25519_PUBLIC_KEY_TEXT_LEN
        && public_key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

#[cfg(test)]
mod tests {
    use super::{
        EncryptedChatMessage, PlaintextChatMessage, RoutedEncryptedMessage,
        is_valid_ed25519_public_key_text, is_valid_username, is_valid_x25519_public_key_text,
    };

    #[test]
    fn wire_round_trip_preserves_sender_and_body() {
        let original = PlaintextChatMessage::new("alice", "bob", "hello bob");

        let encoded = original.to_wire_bytes().expect("message should encode");
        let decoded =
            PlaintextChatMessage::from_wire_bytes(&encoded).expect("message should decode");

        assert_eq!(decoded, original);
    }

    #[test]
    fn invalid_wire_message_is_rejected() {
        let result = PlaintextChatMessage::from_wire_bytes(b"not json");

        assert!(result.is_err());
    }

    #[test]
    fn encrypted_wire_round_trip_preserves_ciphertext_fields() {
        let original = EncryptedChatMessage {
            version: 1,
            sender_encryption_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ciphertext: "unreadable-ciphertext".to_string(),
        };

        let encoded = original.to_wire_bytes().expect("message should encode");
        let decoded =
            EncryptedChatMessage::from_wire_bytes(&encoded).expect("message should decode");

        assert_eq!(decoded, original);
    }

    #[test]
    fn routed_encrypted_wire_round_trip_preserves_route_and_ciphertext() {
        let encrypted = EncryptedChatMessage {
            version: 1,
            sender_encryption_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ciphertext: "unreadable-ciphertext".to_string(),
        };
        let original = RoutedEncryptedMessage::new("alice", "bob", encrypted);

        let encoded = original.to_wire_bytes().expect("message should encode");
        let decoded =
            RoutedEncryptedMessage::from_wire_bytes(&encoded).expect("message should decode");

        assert_eq!(decoded, original);
    }

    #[test]
    fn username_validation_allows_simple_names_only() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("alice.smith-1"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("../alice"));
        assert!(!is_valid_username("alice smith"));
    }

    #[test]
    fn public_key_text_validation_requires_base64url_shape() {
        assert!(is_valid_ed25519_public_key_text(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!is_valid_ed25519_public_key_text("short"));
        assert!(!is_valid_ed25519_public_key_text(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ));
        assert!(is_valid_x25519_public_key_text(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!is_valid_x25519_public_key_text("short"));
    }
}
