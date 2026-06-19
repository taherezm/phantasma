use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use shared::is_valid_username;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug)]
pub struct Identity {
    pub identity_public_key: String,
    pub encryption_public_key: String,
    pub encryption_secret_key: [u8; 32],
    pub path: PathBuf,
    pub was_created: bool,
}

#[derive(Deserialize, Serialize)]
struct StoredIdentity {
    identity_public_key: String,
    identity_secret_key: String,
    encryption_public_key: String,
    encryption_secret_key: String,
}

#[derive(Deserialize)]
struct LegacyStoredIdentity {
    public_key: String,
    secret_key: String,
}

pub fn load_or_create(username: &str) -> anyhow::Result<Identity> {
    let root = identity_root()?;
    load_or_create_in(username, &root)
}

pub fn identity_root() -> anyhow::Result<PathBuf> {
    if let Some(path) = env::var_os("PHANTASMA_HOME") {
        return Ok(PathBuf::from(path));
    }

    if let Some(home) = env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".phantasma"));
    }

    Ok(env::current_dir()?.join(".phantasma"))
}

fn load_or_create_in(username: &str, root: &Path) -> anyhow::Result<Identity> {
    if !is_valid_username(username) {
        bail!("username must use only letters, numbers, '.', '-', or '_'");
    }

    let identity_dir = root.join("identities");
    let path = identity_dir.join(format!("{username}.json"));

    if path.exists() {
        let stored = load_identity_file(&path)?;
        let encryption_secret_key =
            decode_key(&stored.encryption_secret_key, "encryption secret key")?;

        return Ok(Identity {
            identity_public_key: stored.identity_public_key,
            encryption_public_key: stored.encryption_public_key,
            encryption_secret_key,
            path,
            was_created: false,
        });
    }

    fs::create_dir_all(&identity_dir)
        .with_context(|| format!("failed to create {}", identity_dir.display()))?;

    let signing_key = SigningKey::generate(&mut OsRng);
    let identity_public_key = encode_key(signing_key.verifying_key().as_bytes());
    let encryption_secret = StaticSecret::random_from_rng(OsRng);
    let encryption_public = X25519PublicKey::from(&encryption_secret);
    let encryption_public_key = encode_key(encryption_public.as_bytes());
    let encryption_secret_key = encryption_secret.to_bytes();
    let stored = StoredIdentity {
        identity_public_key: identity_public_key.clone(),
        identity_secret_key: encode_key(&signing_key.to_bytes()),
        encryption_public_key: encryption_public_key.clone(),
        encryption_secret_key: encode_key(&encryption_secret_key),
    };
    let json = serde_json::to_string_pretty(&stored)?;

    write_secret_file(&path, json.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;

    Ok(Identity {
        identity_public_key,
        encryption_public_key,
        encryption_secret_key,
        path,
        was_created: true,
    })
}

fn load_identity_file(path: &Path) -> anyhow::Result<StoredIdentity> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let stored = if value.get("identity_public_key").is_some() {
        serde_json::from_value::<StoredIdentity>(value)
            .with_context(|| format!("failed to parse {}", path.display()))?
    } else {
        upgrade_legacy_identity(path, value)?
    };

    validate_stored_identity(path, &stored)?;

    Ok(stored)
}

fn validate_stored_identity(path: &Path, stored: &StoredIdentity) -> anyhow::Result<()> {
    let secret_key = decode_key(&stored.identity_secret_key, "identity secret key")?;
    let public_key = decode_key(&stored.identity_public_key, "identity public key")?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    let derived_public_key = signing_key.verifying_key();
    let stored_public_key = VerifyingKey::from_bytes(&public_key)
        .with_context(|| format!("{} contains an invalid identity public key", path.display()))?;

    if derived_public_key != stored_public_key {
        bail!(
            "{} contains an identity public key that does not match its secret key",
            path.display()
        );
    }

    let encryption_secret_key = decode_key(&stored.encryption_secret_key, "encryption secret key")?;
    let encryption_public_key = decode_key(&stored.encryption_public_key, "encryption public key")?;
    let encryption_secret = StaticSecret::from(encryption_secret_key);
    let derived_encryption_public_key = X25519PublicKey::from(&encryption_secret);

    if derived_encryption_public_key.as_bytes() != &encryption_public_key {
        bail!(
            "{} contains an encryption public key that does not match its secret key",
            path.display()
        );
    }

    Ok(())
}

fn upgrade_legacy_identity(
    path: &Path,
    value: serde_json::Value,
) -> anyhow::Result<StoredIdentity> {
    let legacy = serde_json::from_value::<LegacyStoredIdentity>(value)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let signing_key =
        SigningKey::from_bytes(&decode_key(&legacy.secret_key, "identity secret key")?);
    let public_key = decode_key(&legacy.public_key, "identity public key")?;
    let stored_public_key = VerifyingKey::from_bytes(&public_key)
        .with_context(|| format!("{} contains an invalid identity public key", path.display()))?;

    if signing_key.verifying_key() != stored_public_key {
        bail!(
            "{} contains an identity public key that does not match its secret key",
            path.display()
        );
    }

    let encryption_secret = StaticSecret::random_from_rng(OsRng);
    let encryption_public = X25519PublicKey::from(&encryption_secret);
    let encryption_secret_key = encryption_secret.to_bytes();
    let stored = StoredIdentity {
        identity_public_key: legacy.public_key,
        identity_secret_key: legacy.secret_key,
        encryption_public_key: encode_key(encryption_public.as_bytes()),
        encryption_secret_key: encode_key(&encryption_secret_key),
    };
    let json = serde_json::to_string_pretty(&stored)?;

    fs::write(path, json).with_context(|| format!("failed to update {}", path.display()))?;

    Ok(stored)
}

fn encode_key(bytes: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_key(encoded: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .with_context(|| format!("{label} is not valid base64url"))?;

    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be 32 bytes"))
}

#[cfg(unix)]
fn write_secret_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| {
            use std::io::Write;

            file.write_all(contents)
        })
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::load_or_create_in;

    #[test]
    fn saved_identity_loads_with_the_same_public_key() {
        let root = tempfile::tempdir().expect("tempdir should be created");

        let first = load_or_create_in("alice", root.path()).expect("identity should be created");
        let second = load_or_create_in("alice", root.path()).expect("identity should load");

        assert!(first.was_created);
        assert!(!second.was_created);
        assert_eq!(first.identity_public_key, second.identity_public_key);
        assert_eq!(first.encryption_public_key, second.encryption_public_key);
        assert_eq!(first.encryption_secret_key, second.encryption_secret_key);
        assert_eq!(first.path, second.path);
    }
}
