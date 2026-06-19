use shared::{PublicKeyEntry, PublicKeyRegistration};
use sqlx::{Row, SqlitePool};

#[derive(Debug, Eq, PartialEq)]
pub struct QueuedMessage {
    pub id: i64,
    pub payload: Vec<u8>,
}

pub async fn prepare_database(pool: &SqlitePool) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS public_keys (
            username TEXT PRIMARY KEY NOT NULL,
            identity_public_key TEXT NOT NULL DEFAULT '',
            encryption_public_key TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        "#,
    )
    .execute(pool)
    .await?;

    add_column_if_missing(pool, "identity_public_key", "TEXT NOT NULL DEFAULT ''").await?;
    add_column_if_missing(pool, "encryption_public_key", "TEXT NOT NULL DEFAULT ''").await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS queued_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            payload BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS queued_messages_recipient_id
        ON queued_messages (recipient, id)
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn add_column_if_missing(
    pool: &SqlitePool,
    column_name: &str,
    column_definition: &str,
) -> sqlx::Result<()> {
    let columns = sqlx::query("PRAGMA table_info(public_keys)")
        .fetch_all(pool)
        .await?;
    let exists = columns
        .iter()
        .any(|row| row.get::<String, _>("name") == column_name);

    if !exists {
        let query = format!("ALTER TABLE public_keys ADD COLUMN {column_name} {column_definition}");
        sqlx::query(&query).execute(pool).await?;
    }

    Ok(())
}

pub async fn register_public_key(
    pool: &SqlitePool,
    registration: &PublicKeyRegistration,
) -> sqlx::Result<PublicKeyEntry> {
    sqlx::query(
        r#"
        INSERT INTO public_keys (
            username,
            identity_public_key,
            encryption_public_key,
            updated_at
        )
        VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        ON CONFLICT(username) DO UPDATE SET
            identity_public_key = excluded.identity_public_key,
            encryption_public_key = excluded.encryption_public_key,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&registration.username)
    .bind(&registration.identity_public_key)
    .bind(&registration.encryption_public_key)
    .execute(pool)
    .await?;

    Ok(PublicKeyEntry {
        username: registration.username.clone(),
        identity_public_key: registration.identity_public_key.clone(),
        encryption_public_key: registration.encryption_public_key.clone(),
    })
}

pub async fn lookup_public_key(
    pool: &SqlitePool,
    username: &str,
) -> sqlx::Result<Option<PublicKeyEntry>> {
    let row = sqlx::query(
        r#"
        SELECT username, identity_public_key, encryption_public_key
        FROM public_keys
        WHERE username = ?
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| PublicKeyEntry {
        username: row.get("username"),
        identity_public_key: row.get("identity_public_key"),
        encryption_public_key: row.get("encryption_public_key"),
    }))
}

pub async fn queue_message(pool: &SqlitePool, recipient: &str, payload: &[u8]) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO queued_messages (recipient, payload)
        VALUES (?, ?)
        "#,
    )
    .bind(recipient)
    .bind(payload)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn queued_messages_for(
    pool: &SqlitePool,
    recipient: &str,
) -> sqlx::Result<Vec<QueuedMessage>> {
    let rows = sqlx::query(
        r#"
        SELECT id, payload
        FROM queued_messages
        WHERE recipient = ?
        ORDER BY id
        "#,
    )
    .bind(recipient)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| QueuedMessage {
            id: row.get("id"),
            payload: row.get("payload"),
        })
        .collect())
}

pub async fn delete_queued_message(pool: &SqlitePool, id: i64) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        DELETE FROM queued_messages
        WHERE id = ?
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        delete_queued_message, lookup_public_key, prepare_database, queue_message,
        queued_messages_for, register_public_key,
    };
    use shared::PublicKeyRegistration;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn registering_key_then_looking_it_up_returns_same_key() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory database should open");
        prepare_database(&pool)
            .await
            .expect("database should initialize");

        let identity_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let encryption_public_key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let registration =
            PublicKeyRegistration::new("alice", identity_public_key, encryption_public_key);

        register_public_key(&pool, &registration)
            .await
            .expect("registration should be stored");
        let looked_up = lookup_public_key(&pool, "alice")
            .await
            .expect("lookup should query database")
            .expect("registered key should exist");

        assert_eq!(looked_up.username, "alice");
        assert_eq!(looked_up.identity_public_key, identity_public_key);
        assert_eq!(looked_up.encryption_public_key, encryption_public_key);
    }

    #[tokio::test]
    async fn queued_message_can_be_read_then_deleted() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory database should open");
        prepare_database(&pool)
            .await
            .expect("database should initialize");

        let payload = b"encrypted bytes only";

        queue_message(&pool, "bob", payload)
            .await
            .expect("message should be queued");
        let queued = queued_messages_for(&pool, "bob")
            .await
            .expect("queued messages should load");

        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].payload, payload);

        delete_queued_message(&pool, queued[0].id)
            .await
            .expect("queued message should delete");
        let queued = queued_messages_for(&pool, "bob")
            .await
            .expect("queued messages should load");

        assert!(queued.is_empty());
    }
}
