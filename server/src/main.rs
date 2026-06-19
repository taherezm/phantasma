use axum::{
    Router,
    extract::{
        Json, Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Method, StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt};
use shared::{
    PublicKeyEntry, PublicKeyRegistration, RoutedEncryptedMessage,
    is_valid_ed25519_public_key_text, is_valid_username, is_valid_x25519_public_key_text,
};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{Mutex, mpsc};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod directory;

const DEFAULT_DATABASE_URL: &str = "sqlite://phantasma.sqlite";

#[derive(Clone)]
struct AppState {
    active_clients: Arc<Mutex<HashMap<String, ActiveClient>>>,
    directory: SqlitePool,
    next_connection_id: Arc<AtomicU64>,
}

#[derive(Clone, Debug)]
struct ActiveClient {
    connection_id: u64,
    sender: mpsc::UnboundedSender<Vec<u8>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "server=info".into()))
        .init();

    let directory = open_directory_database().await?;
    directory::prepare_database(&directory).await?;

    let state = AppState {
        active_clients: Arc::new(Mutex::new(HashMap::new())),
        directory,
        next_connection_id: Arc::new(AtomicU64::new(1)),
    };

    let app = Router::new()
        .route("/", get(|| async { "Phantasma relay server\n" }))
        .route("/users", post(register_public_key))
        .route("/users/{username}/public-key", get(lookup_public_key))
        .route("/ws/{username}", get(websocket_handler))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([CONTENT_TYPE]),
        )
        .with_state(state);

    let address: SocketAddr = "127.0.0.1:3000".parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;

    println!("listening on ws://{address}/ws");
    info!("listening on ws://{address}/ws");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn open_directory_database() -> anyhow::Result<SqlitePool> {
    let database_url =
        env::var("PHANTASMA_DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());
    let options = SqliteConnectOptions::from_str(&database_url)?.create_if_missing(true);

    Ok(SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?)
}

async fn register_public_key(
    State(state): State<AppState>,
    Json(registration): Json<PublicKeyRegistration>,
) -> Result<(StatusCode, Json<PublicKeyEntry>), (StatusCode, String)> {
    validate_registration(&registration)?;

    let entry = directory::register_public_key(&state.directory, &registration)
        .await
        .map_err(internal_error)?;

    Ok((StatusCode::CREATED, Json(entry)))
}

async fn lookup_public_key(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<PublicKeyEntry>, (StatusCode, String)> {
    if !is_valid_username(&username) {
        return Err((
            StatusCode::BAD_REQUEST,
            "username must use only letters, numbers, '.', '-', or '_'".to_string(),
        ));
    }

    match directory::lookup_public_key(&state.directory, &username)
        .await
        .map_err(internal_error)?
    {
        Some(entry) => Ok(Json(entry)),
        None => Err((StatusCode::NOT_FOUND, "public key not found".to_string())),
    }
}

fn validate_registration(registration: &PublicKeyRegistration) -> Result<(), (StatusCode, String)> {
    if !is_valid_username(&registration.username) {
        return Err((
            StatusCode::BAD_REQUEST,
            "username must use only letters, numbers, '.', '-', or '_'".to_string(),
        ));
    }

    if !is_valid_ed25519_public_key_text(&registration.identity_public_key) {
        return Err((
            StatusCode::BAD_REQUEST,
            "public key must be a base64url Ed25519 public key".to_string(),
        ));
    }

    if !is_valid_x25519_public_key_text(&registration.encryption_public_key) {
        return Err((
            StatusCode::BAD_REQUEST,
            "encryption public key must be a base64url X25519 public key".to_string(),
        ));
    }

    Ok(())
}

fn internal_error(err: sqlx::Error) -> (StatusCode, String) {
    error!(%err, "directory database error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "directory database error".to_string(),
    )
}

async fn websocket_handler(
    Path(username): Path<String>,
    websocket: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !is_valid_username(&username) {
        return Err((
            StatusCode::BAD_REQUEST,
            "username must use only letters, numbers, '.', '-', or '_'".to_string(),
        ));
    }

    Ok(websocket.on_upgrade(move |socket| handle_socket(username, socket, state)))
}

async fn handle_socket(username: String, socket: WebSocket, state: AppState) {
    let connection_id = state.next_connection_id.fetch_add(1, Ordering::Relaxed);
    let (mut socket_sender, mut socket_receiver) = socket.split();
    let (outbound_sender, mut outbound_receiver) = mpsc::unbounded_channel::<Vec<u8>>();

    {
        let mut active_clients = state.active_clients.lock().await;
        active_clients.insert(
            username.clone(),
            ActiveClient {
                connection_id,
                sender: outbound_sender.clone(),
            },
        );
    }

    info!(connection_id, username, "client connected");
    deliver_queued_messages(&state, &username, &outbound_sender).await;

    let mut send_task = tokio::spawn(async move {
        while let Some(payload) = outbound_receiver.recv().await {
            if socket_sender
                .send(Message::Binary(payload.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let receive_state = state.clone();
    let receive_username = username.clone();
    let mut receive_task = tokio::spawn(async move {
        while let Some(result) = socket_receiver.next().await {
            match result {
                Ok(Message::Binary(bytes)) => {
                    if let Err(err) =
                        handle_encrypted_payload(&receive_state, &receive_username, bytes.to_vec())
                            .await
                    {
                        error!(connection_id, %err, "failed to handle encrypted payload");
                    }
                }
                Ok(Message::Text(text)) => {
                    println!(
                        "server rejected plaintext websocket text frame: {} characters",
                        text.len()
                    );
                }
                Ok(Message::Close(_)) => break,
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                Err(err) => {
                    error!(connection_id, %err, "websocket error");
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => receive_task.abort(),
        _ = &mut receive_task => send_task.abort(),
    }

    {
        let mut active_clients = state.active_clients.lock().await;
        let should_remove = active_clients
            .get(&username)
            .is_some_and(|active_client| active_client.connection_id == connection_id);

        if should_remove {
            active_clients.remove(&username);
        }
    }

    info!(connection_id, username, "client disconnected");
}

async fn handle_encrypted_payload(
    state: &AppState,
    sender_username: &str,
    payload: Vec<u8>,
) -> anyhow::Result<()> {
    let routed = RoutedEncryptedMessage::from_wire_bytes(&payload)?;
    let encrypted_payload = routed.encrypted.to_wire_bytes()?;

    if routed.from != sender_username {
        println!(
            "server rejected encrypted payload claiming to be from {} on {}'s connection",
            routed.from, sender_username
        );
        return Ok(());
    }

    if !is_valid_username(&routed.to) {
        println!("server rejected encrypted payload for invalid recipient");
        return Ok(());
    }

    let recipient = {
        let active_clients = state.active_clients.lock().await;
        active_clients.get(&routed.to).cloned()
    };

    if let Some(recipient) = recipient
        && recipient.sender.send(encrypted_payload.clone()).is_ok()
    {
        println!(
            "server relayed encrypted payload to {}: {} bytes hex={}",
            routed.to,
            encrypted_payload.len(),
            hex_preview(&encrypted_payload)
        );
        return Ok(());
    }

    directory::queue_message(&state.directory, &routed.to, &encrypted_payload).await?;
    println!(
        "server queued encrypted payload for {}: {} bytes hex={}",
        routed.to,
        encrypted_payload.len(),
        hex_preview(&encrypted_payload)
    );

    Ok(())
}

async fn deliver_queued_messages(
    state: &AppState,
    username: &str,
    sender: &mpsc::UnboundedSender<Vec<u8>>,
) {
    let queued_messages = match directory::queued_messages_for(&state.directory, username).await {
        Ok(messages) => messages,
        Err(err) => {
            error!(%err, username, "failed to load queued messages");
            return;
        }
    };

    for queued_message in queued_messages {
        if sender.send(queued_message.payload.clone()).is_err() {
            break;
        }

        if let Err(err) =
            directory::delete_queued_message(&state.directory, queued_message.id).await
        {
            error!(%err, username, "failed to delete delivered queued message");
            break;
        }

        println!(
            "server delivered queued encrypted payload to {username}: {} bytes hex={}",
            queued_message.payload.len(),
            hex_preview(&queued_message.payload)
        );
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let limit = 96;
    let mut preview = String::new();

    for byte in bytes.iter().take(limit) {
        let _ = write!(&mut preview, "{byte:02x}");
    }

    if bytes.len() > limit {
        preview.push_str("...");
    }

    preview
}
