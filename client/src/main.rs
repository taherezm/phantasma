use anyhow::bail;
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use shared::{EncryptedChatMessage, PublicKeyEntry, RoutedEncryptedMessage};
use std::env;
use tokio::{
    io::{self, AsyncBufReadExt, BufReader},
    net::TcpStream,
    time::Duration,
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

mod contacts;
mod crypto;
mod identity;
mod server_api;

type ClientSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type SocketWriter = SplitSink<ClientSocket, Message>;
type SocketReader = SplitStream<ClientSocket>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Some((name, endpoints)) = read_args()? else {
        return Ok(());
    };
    let identity = identity::load_or_create(&name)?;
    let mut contacts = contacts::ContactBook::load_or_create(&name)?;
    let http_client = reqwest::Client::new();

    if identity.was_created {
        println!("created identity at {}", identity.path.display());
    } else {
        println!("loaded identity from {}", identity.path.display());
    }

    server_api::register_public_key(
        &http_client,
        &endpoints,
        &name,
        &identity.identity_public_key,
        &identity.encryption_public_key,
    )
    .await?;
    println!("registered public key for {name}");

    let websocket_url = endpoints.websocket_url(&name);
    let (mut socket_writer, mut socket_reader) = connect_with_retry(&websocket_url).await?;

    println!("username: {name}");
    print_help();

    let stdin = BufReader::new(io::stdin());
    let mut stdin_lines = stdin.lines();

    loop {
        tokio::select! {
            line = stdin_lines.next_line() => {
                let Some(line) = line? else {
                    break;
                };

                let command = line.trim();

                if command.is_empty() {
                    continue;
                }

                if command == "/quit" {
                    break;
                }

                if command == "/help" {
                    print_help();
                    continue;
                }

                if command == "/contacts" {
                    print_contacts(&contacts);
                    continue;
                }

                if let Some(username) = command.strip_prefix("/add ") {
                    add_contact(&http_client, &endpoints, &mut contacts, username.trim()).await?;
                    continue;
                }

                if let Some(rest) = command.strip_prefix("/send ") {
                    if let Err(err) = send_message(
                        &http_client,
                        &endpoints,
                        &mut contacts,
                        &mut socket_writer,
                        &name,
                        &identity,
                        rest,
                    )
                    .await
                    {
                        println!("send failed: {err}");
                    }
                    continue;
                }

                if let Some(rest) = command.strip_prefix("/to ") {
                    if let Err(err) = send_message(
                        &http_client,
                        &endpoints,
                        &mut contacts,
                        &mut socket_writer,
                        &name,
                        &identity,
                        rest,
                    )
                    .await
                    {
                        println!("send failed: {err}");
                    }
                    continue;
                }

                if let Some(username) = command.strip_prefix("/lookup ") {
                    add_contact(&http_client, &endpoints, &mut contacts, username.trim()).await?;
                    continue;
                }

                println!("unknown command. type /help.");
            }
            message = socket_reader.next() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        if let Err(err) = receive_message(
                            &http_client,
                            &endpoints,
                            &mut contacts,
                            &name,
                            &identity,
                            &bytes,
                        )
                        .await
                        {
                            println!("received message could not be opened: {err}");
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        println!(
                            "received unexpected plaintext frame with {} characters",
                            text.len()
                        );
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        println!("connection lost. reconnecting.");
                        (socket_writer, socket_reader) = connect_with_retry(&websocket_url).await?;
                    }
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                    Some(Err(err)) => {
                        println!("connection error: {err}. reconnecting.");
                        (socket_writer, socket_reader) = connect_with_retry(&websocket_url).await?;
                    }
                }
            }
        }
    }

    let _ = socket_writer.close().await;

    Ok(())
}

async fn connect_with_retry(url: &str) -> anyhow::Result<(SocketWriter, SocketReader)> {
    loop {
        match connect_async(url).await {
            Ok((socket, _)) => {
                println!("connected to server");
                return Ok(socket.split());
            }
            Err(err) => {
                println!("connection failed: {err}. retrying in 2 seconds.");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn add_contact(
    http_client: &reqwest::Client,
    endpoints: &server_api::ServerEndpoints,
    contacts: &mut contacts::ContactBook,
    username: &str,
) -> anyhow::Result<()> {
    if username.is_empty() {
        println!("usage: /add <username>");
        return Ok(());
    }

    match server_api::lookup_public_key(http_client, endpoints, username).await? {
        Some(entry) => {
            contacts.add(entry)?;
            println!("added contact {username}");
        }
        None => println!("no public key found for {username}"),
    }

    Ok(())
}

async fn send_message(
    http_client: &reqwest::Client,
    endpoints: &server_api::ServerEndpoints,
    contacts: &mut contacts::ContactBook,
    socket_writer: &mut SocketWriter,
    sender_name: &str,
    identity: &identity::Identity,
    rest: &str,
) -> anyhow::Result<()> {
    let Some((recipient, message_body)) = rest.trim().split_once(' ') else {
        println!("usage: /send <username> <message>");
        return Ok(());
    };
    let recipient = recipient.trim();
    let message_body = message_body.trim();

    if recipient.is_empty() || message_body.is_empty() {
        println!("usage: /send <username> <message>");
        return Ok(());
    }

    let recipient_entry = match contacts.get(recipient) {
        Some(entry) => entry.clone(),
        None => match server_api::lookup_public_key(http_client, endpoints, recipient).await? {
            Some(entry) => {
                contacts.add(entry.clone())?;
                println!("added contact {recipient}");
                entry
            }
            None => {
                println!(
                    "no public key found for {recipient}. use /add {recipient} after they register."
                );
                return Ok(());
            }
        },
    };

    let encrypted = crypto::encrypt_message(
        sender_name,
        recipient,
        message_body,
        &identity.encryption_secret_key,
        &identity.encryption_public_key,
        &recipient_entry.encryption_public_key,
    )?;
    let routed = RoutedEncryptedMessage::new(sender_name, recipient, encrypted);
    let wire_message = routed.to_wire_bytes()?;

    socket_writer
        .send(Message::Binary(wire_message.into()))
        .await?;
    println!("sent encrypted message to {recipient}");

    Ok(())
}

async fn receive_message(
    http_client: &reqwest::Client,
    endpoints: &server_api::ServerEndpoints,
    contacts: &mut contacts::ContactBook,
    receiver_name: &str,
    identity: &identity::Identity,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let encrypted = EncryptedChatMessage::from_wire_bytes(bytes)?;
    let chat_message = crypto::decrypt_message(
        &identity.encryption_secret_key,
        &identity.encryption_public_key,
        &encrypted,
    )?;

    if chat_message.to != receiver_name {
        return Ok(());
    }

    let sender_entry =
        find_or_add_sender(http_client, endpoints, contacts, &chat_message.from).await?;

    if sender_entry.encryption_public_key != encrypted.sender_encryption_public_key {
        bail!("sender key did not match saved contact");
    }

    println!("{}: {}", chat_message.from, chat_message.body);

    Ok(())
}

async fn find_or_add_sender(
    http_client: &reqwest::Client,
    endpoints: &server_api::ServerEndpoints,
    contacts: &mut contacts::ContactBook,
    username: &str,
) -> anyhow::Result<PublicKeyEntry> {
    if let Some(entry) = contacts.get(username) {
        return Ok(entry.clone());
    }

    let Some(entry) = server_api::lookup_public_key(http_client, endpoints, username).await? else {
        bail!("no public key found for sender {username}");
    };

    contacts.add(entry.clone())?;
    println!("added contact {username}");

    Ok(entry)
}

fn print_contacts(contacts: &contacts::ContactBook) {
    let names: Vec<_> = contacts.names().collect();

    if names.is_empty() {
        println!("no contacts yet");
        return;
    }

    for name in names {
        println!("{name}");
    }
}

fn print_help() {
    println!("commands:");
    println!("  /add <username>             add or refresh a contact");
    println!("  /contacts                   list saved contacts");
    println!("  /send <username> <message>  send an encrypted message");
    println!("  /quit                       exit");
}

fn read_args() -> anyhow::Result<Option<(String, server_api::ServerEndpoints)>> {
    let mut args = env::args().skip(1);
    let mut name = None;
    let mut server = None;
    let mut positional = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(None);
            }
            "--username" | "-u" => {
                let Some(value) = args.next() else {
                    bail!("--username needs a value");
                };
                name = Some(value);
            }
            "--server" | "-s" => {
                let Some(value) = args.next() else {
                    bail!("--server needs a value");
                };
                server = Some(value);
            }
            _ if arg.starts_with('-') => bail!("unknown option {arg}"),
            _ => positional.push(arg),
        }
    }

    if name.is_none() && !positional.is_empty() {
        name = Some(positional.remove(0));
    }

    if server.is_none() && !positional.is_empty() {
        server = Some(positional.remove(0));
    }

    if !positional.is_empty() {
        bail!("too many arguments");
    }

    let Some(name) = name else {
        print_usage();
        bail!("username is required");
    };
    let endpoints = server_api::ServerEndpoints::from_optional_arg(server)?;

    Ok(Some((name, endpoints)))
}

fn print_usage() {
    println!("usage: cargo run -p client -- --username <name> [--server http://127.0.0.1:3000]");
    println!("short form still works: cargo run -p client -- <name>");
}
