use anyhow::{Context, bail};
use shared::{PublicKeyEntry, PublicKeyRegistration, is_valid_username};

#[derive(Clone, Debug)]
pub struct ServerEndpoints {
    pub http_base_url: String,
    websocket_base_url: String,
}

impl ServerEndpoints {
    pub fn from_optional_arg(arg: Option<String>) -> anyhow::Result<Self> {
        let raw = arg.unwrap_or_else(|| "http://127.0.0.1:3000".to_string());
        let trimmed = raw.trim_end_matches('/');

        if let Some(rest) = trimmed.strip_prefix("http://") {
            return Ok(Self {
                http_base_url: format!("http://{rest}"),
                websocket_base_url: format!("ws://{rest}"),
            });
        }

        if let Some(rest) = trimmed.strip_prefix("https://") {
            return Ok(Self {
                http_base_url: format!("https://{rest}"),
                websocket_base_url: format!("wss://{rest}"),
            });
        }

        if let Some(rest) = trimmed.strip_prefix("ws://") {
            let rest = rest.strip_suffix("/ws").unwrap_or(rest);
            return Ok(Self {
                http_base_url: format!("http://{rest}"),
                websocket_base_url: format!("ws://{rest}"),
            });
        }

        if let Some(rest) = trimmed.strip_prefix("wss://") {
            let rest = rest.strip_suffix("/ws").unwrap_or(rest);
            return Ok(Self {
                http_base_url: format!("https://{rest}"),
                websocket_base_url: format!("wss://{rest}"),
            });
        }

        bail!("server must start with http://, https://, ws://, or wss://");
    }

    pub fn websocket_url(&self, username: &str) -> String {
        format!("{}/ws/{username}", self.websocket_base_url)
    }
}

pub async fn register_public_key(
    http_client: &reqwest::Client,
    endpoints: &ServerEndpoints,
    username: &str,
    identity_public_key: &str,
    encryption_public_key: &str,
) -> anyhow::Result<()> {
    let url = format!("{}/users", endpoints.http_base_url);
    let registration =
        PublicKeyRegistration::new(username, identity_public_key, encryption_public_key);
    let response = http_client
        .post(&url)
        .json(&registration)
        .send()
        .await
        .with_context(|| format!("failed to register public key at {url}"))?;

    ensure_success(response).await?;

    Ok(())
}

pub async fn lookup_public_key(
    http_client: &reqwest::Client,
    endpoints: &ServerEndpoints,
    username: &str,
) -> anyhow::Result<Option<PublicKeyEntry>> {
    if !is_valid_username(username) {
        bail!("username must use only letters, numbers, '.', '-', or '_'");
    }

    let url = format!("{}/users/{}/public-key", endpoints.http_base_url, username);
    let response = http_client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to look up public key at {url}"))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let response = ensure_success(response).await?;
    let entry = response.json::<PublicKeyEntry>().await?;

    Ok(Some(entry))
}

async fn ensure_success(response: reqwest::Response) -> anyhow::Result<reqwest::Response> {
    let status = response.status();

    if status.is_success() {
        return Ok(response);
    }

    let body = response.text().await.unwrap_or_else(|_| String::new());

    if body.is_empty() {
        bail!("server returned {status}");
    }

    bail!("server returned {status}: {body}");
}
