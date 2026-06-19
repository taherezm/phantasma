use anyhow::Context;
use serde::{Deserialize, Serialize};
use shared::{PublicKeyEntry, is_valid_username};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct ContactBook {
    contacts: BTreeMap<String, PublicKeyEntry>,
    path: PathBuf,
}

#[derive(Default, Deserialize, Serialize)]
struct StoredContacts {
    contacts: BTreeMap<String, PublicKeyEntry>,
}

impl ContactBook {
    pub fn load_or_create(owner_username: &str) -> anyhow::Result<Self> {
        let root = crate::identity::identity_root()?;
        Self::load_or_create_in(owner_username, &root)
    }

    pub fn add(&mut self, entry: PublicKeyEntry) -> anyhow::Result<()> {
        self.contacts.insert(entry.username.clone(), entry);
        self.save()
    }

    pub fn get(&self, username: &str) -> Option<&PublicKeyEntry> {
        self.contacts.get(username)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.contacts.keys().map(String::as_str)
    }

    fn load_or_create_in(owner_username: &str, root: &Path) -> anyhow::Result<Self> {
        if !is_valid_username(owner_username) {
            anyhow::bail!("username must use only letters, numbers, '.', '-', or '_'");
        }

        let contacts_dir = root.join("contacts");
        let path = contacts_dir.join(format!("{owner_username}.json"));

        if path.exists() {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let stored: StoredContacts = serde_json::from_str(&text)
                .with_context(|| format!("failed to parse {}", path.display()))?;

            return Ok(Self {
                contacts: stored.contacts,
                path,
            });
        }

        fs::create_dir_all(&contacts_dir)
            .with_context(|| format!("failed to create {}", contacts_dir.display()))?;

        let contact_book = Self {
            contacts: BTreeMap::new(),
            path,
        };
        contact_book.save()?;

        Ok(contact_book)
    }

    fn save(&self) -> anyhow::Result<()> {
        let stored = StoredContacts {
            contacts: self.contacts.clone(),
        };
        let json = serde_json::to_string_pretty(&stored)?;

        fs::write(&self.path, json)
            .with_context(|| format!("failed to write {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::ContactBook;
    use shared::PublicKeyEntry;

    #[test]
    fn saved_contact_loads_on_next_run() {
        let root = tempfile::tempdir().expect("tempdir should be created");
        let contact = PublicKeyEntry {
            username: "bob".to_string(),
            identity_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            encryption_public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        };

        let mut first =
            ContactBook::load_or_create_in("alice", root.path()).expect("contacts should load");
        first.add(contact).expect("contact should save");
        let second =
            ContactBook::load_or_create_in("alice", root.path()).expect("contacts should reload");

        assert!(second.get("bob").is_some());
    }
}
