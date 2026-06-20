# Phantasma

Phantasma is a small end-to-end encrypted messenger built in Rust for private communication between friends.

The project began with one architectural rule:

> The relay server may transport and store messages, but it should never receive their plaintext contents.

Phantasma uses a client-relay-client architecture. Each user runs a command-line client on their own device. One machine runs the relay server. Messages are encrypted by the sender before they leave the sender’s computer and are decrypted only by the recipient’s client.

I tested the system across two different computers and operating systems:

* Alice ran the client on macOS.
* Bob ran the client on Windows.
* The relay ran on Alice’s Mac.
* Tailscale created the private network connection between the two computers.
* Both users communicated through their terminals over a long-distance connection.

## What This Project Demonstrates

Phantasma is an educational implementation of several systems concepts:

* End-to-end encrypted message transport
* Public-key discovery
* Local identity persistence
* Authenticated encryption
* WebSocket-based real-time delivery
* Offline encrypted-message queueing
* SQLite-backed server persistence
* Cross-platform Rust clients
* Private networking through Tailscale
* A relay that routes ciphertext rather than plaintext

Phantasma is a learning project, not a security-audited replacement for Signal or another production messenger.

---

## Architecture

```text
┌───────────────────────────┐
│ Alice's Mac               │
│                           │
│  Phantasma CLI Client     │
│  - Alice's private keys   │
│  - Alice's contacts       │
│  - Local encryption       │
│  - Local decryption       │
└─────────────┬─────────────┘
              │
              │ HTTP + WebSocket
              │ over Tailscale
              │
┌─────────────▼─────────────┐
│ Phantasma Relay Server    │
│ Running on Alice's Mac    │
│                           │
│  - Public-key directory   │
│  - WebSocket connections  │
│  - Encrypted message      │
│    routing                │
│  - SQLite offline queue   │
│                           │
│  No plaintext messages    │
└─────────────┬─────────────┘
              │
              │ HTTP + WebSocket
              │ over Tailscale
              │
┌─────────────▼─────────────┐
│ Bob's Windows Computer    │
│                           │
│  Phantasma CLI Client     │
│  - Bob's private keys     │
│  - Bob's contacts         │
│  - Local encryption       │
│  - Local decryption       │
└───────────────────────────┘
```

Tailscale is not part of the encryption protocol. It acts as the private network path that allows two computers on different internet connections to reach the relay without exposing the relay directly to the public internet.

The Phantasma clients still perform the message encryption and decryption.

---

## Repository Structure

```text
phantasma/
├── client/     Rust command-line client
├── server/     Rust relay server
├── shared/     Shared protocol and data types
├── docs/       Optional static browser client
├── deploy/     Deployment documentation
├── Cargo.toml  Rust workspace manifest
└── Cargo.lock  Locked dependency versions
```

### `client`

The command-line client handles:

* Local identity creation
* Local private-key storage
* Public-key registration
* Contact lookup
* Message encryption
* Message decryption
* WebSocket delivery
* Terminal commands

### `server`

The relay server handles:

* Username and public-key registration
* Public-key lookup
* Active WebSocket connections
* Ciphertext forwarding
* Offline ciphertext storage
* SQLite persistence

### `shared`

The shared crate contains message, directory, and protocol types used by both the client and server.

### `docs`

The `docs` directory contains an optional browser implementation. The terminal client does not require the browser client or GitHub Pages.

---

## Message Flow

Suppose Alice wants to send Bob a message.

### 1. Bob creates an identity

Bob’s client generates private keys locally and stores them on Bob’s computer.

Only Bob’s public keys are registered with the relay.

### 2. Alice adds Bob

Alice runs:

```text
/add bob
```

Alice’s client requests Bob’s public key from the relay and saves Bob as a local contact.

### 3. Alice sends a message

Alice runs:

```text
/send bob hello
```

Alice’s client:

1. Loads Bob’s public encryption key.
2. Performs X25519 key agreement.
3. Derives a message key through HKDF-SHA256.
4. Encrypts the plaintext using XChaCha20-Poly1305.
5. Sends the encrypted envelope to the relay.

### 4. The relay routes ciphertext

The relay does not need the message key.

If Bob is online, the relay forwards the encrypted envelope through Bob’s WebSocket connection.

If Bob is offline, the relay stores the encrypted envelope in SQLite until Bob reconnects.

### 5. Bob decrypts locally

Bob’s client receives the encrypted envelope, derives the corresponding message key, authenticates the ciphertext, and decrypts the message on Bob’s device.

The terminal then displays:

```text
alice: hello
```

---

## Cryptography

The Rust client uses established cryptographic crates rather than custom cryptographic primitives:

* [`x25519-dalek`](https://crates.io/crates/x25519-dalek) for X25519 key agreement
* [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) for XChaCha20-Poly1305 authenticated encryption
* [`hkdf`](https://crates.io/crates/hkdf) and [`sha2`](https://crates.io/crates/sha2) for message-key derivation
* [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) for long-term identity keys

The browser client uses:

* `libsodium.js` for X25519 and XChaCha20-Poly1305
* WebCrypto HKDF-SHA256 for compatible key derivation

Using established libraries does not by itself make an application secure. Protocol design, identity verification, key rotation, replay protection, metadata handling, and implementation review still matter.

---

# Running Phantasma Locally

The simplest test uses one relay and two clients on the same computer.

## Requirements

Install a current stable Rust toolchain:

```sh
rustup update stable
rustup default stable
```

Verify:

```sh
rustc --version
cargo --version
```

This project uses Rust Edition 2024 and therefore requires Rust and Cargo 1.85 or newer.

## Build the workspace

```sh
git clone https://github.com/taherezm/phantasma.git
cd phantasma
cargo build --workspace
```

## Run the tests

```sh
cargo test --workspace
```

## Start the relay

```sh
cargo run -p server
```

The local relay listens at:

```text
http://127.0.0.1:3000
```

The WebSocket endpoint is:

```text
ws://127.0.0.1:3000/ws
```

## Start Alice

In another terminal:

```sh
cargo run -p client -- \
  --username alice \
  --server http://127.0.0.1:3000
```

## Start Bob

In a third terminal:

```sh
cargo run -p client -- \
  --username bob \
  --server http://127.0.0.1:3000
```

## Add contacts

Alice:

```text
/add bob
```

Bob:

```text
/add alice
```

## Send messages

Alice:

```text
/send bob hello from alice
```

Bob:

```text
/send alice hello from bob
```

---

# Long-Distance Terminal Setup

The local test proves that the relay and clients work, but `127.0.0.1` is only reachable from the same computer.

To communicate between different homes or networks, the relay must be reachable from the other user’s device.

For our test, we used Tailscale.

## Why Tailscale?

Without Tailscale, the relay host would ordinarily need to:

* Configure router port forwarding
* Expose a public port
* Handle changing public IP addresses
* Configure firewall rules
* Potentially work around carrier-grade NAT
* Add HTTPS and secure WebSocket termination

Tailscale gives each computer a private `100.x.x.x` address and creates an encrypted device-to-device network.

Phantasma still handles application-layer message encryption. Tailscale provides the network route.

---

## Tested Network Topology

```text
Alice's Mac
Tailscale IP: 100.x.x.x
├── Phantasma relay
└── Alice client

Bob's Windows PC
Tailscale IP: 100.y.y.y
└── Bob client
```

Only Alice’s Mac ran the relay.

Bob did not run a second server.

---

# Host Setup: macOS

These are the steps for the computer hosting the relay.

## 1. Install and connect Tailscale

Install Tailscale and sign in.

Confirm that the Mac appears under the Tailscale **Machines** page.

Find the Mac’s Tailscale IP. It will resemble:

```text
100.88.202.123
```

Do not copy this example literally. Use the address assigned to your machine.

The examples below use:

```text
100.x.x.x
```

## 2. Build Phantasma

```sh
cd /path/to/phantasma
cargo build --workspace
```

## 3. Start the relay on the Tailscale interface

```sh
PHANTASMA_BIND_ADDR=100.x.x.x:3000 \
PHANTASMA_DATABASE_URL=sqlite://phantasma.sqlite \
./target/debug/server
```

A successful startup should display something resembling:

```text
listening on ws://100.x.x.x:3000/ws
```

Leave this terminal open.

### Alternative bind address

If binding directly to the Tailscale address fails, the server can listen on all interfaces:

```sh
PHANTASMA_BIND_ADDR=0.0.0.0:3000 \
PHANTASMA_DATABASE_URL=sqlite://phantasma.sqlite \
./target/debug/server
```

Binding to the specific Tailscale address is narrower and preferable when possible.

## 4. Start Alice

Open another terminal:

```sh
cd /path/to/phantasma

./target/debug/client \
  --username alice \
  --server http://100.x.x.x:3000
```

On the first run, Alice’s identity is created.

On later runs, the existing identity is loaded:

```text
loaded identity from ~/.phantasma/identities/alice.json
registered public key for alice
connected to server
username: alice
```

---

# Friend Setup: Windows

These are the steps used for the remote Windows client.

## 1. Join the same Tailscale network

The relay host invites the friend to the Tailscale network.

The friend must:

1. Accept the invitation.
2. Install Tailscale.
3. Sign in using the invited account.
4. Confirm that Tailscale says connected.
5. Confirm that the Windows computer appears under **Machines**.

Appearing under **Users** is not enough. The device itself must appear under **Machines**.

## 2. Test relay connectivity

Open PowerShell:

```powershell
Test-NetConnection -ComputerName 100.x.x.x -Port 3000
```

A successful result includes:

```text
TcpTestSucceeded : True
```

This confirms that the Windows computer can reach the relay through Tailscale.

## 3. Install Git and Rust

Verify:

```powershell
git --version
rustc --version
cargo --version
```

If Rust is outdated, update it:

```powershell
rustup update stable
rustup default stable
```

Verify again:

```powershell
rustc --version
cargo --version
```

Phantasma uses Rust Edition 2024, so Cargo 1.83 will fail with:

```text
feature `edition2024` is required
```

Updating to stable Rust 1.85 or newer resolves this.

## 4. Clone Phantasma

For a private repository, the friend must first be added as a GitHub collaborator.

Then:

```powershell
cd $HOME\Documents
git clone https://github.com/taherezm/phantasma.git
cd phantasma
```

## 5. Build the client

```powershell
cargo build -p client
```

The friend only needs the client. The friend does not run the relay server.

## 6. Start Bob

```powershell
.\target\debug\client.exe `
  --username bob `
  --server http://100.x.x.x:3000
```

A successful first connection should resemble:

```text
created identity
registered public key for bob
connected to server
username: bob
```

At the same time, the relay terminal should report that Bob connected.

---

# Starting the Conversation

Once Alice and Bob are connected:

## Alice adds Bob

```text
/add bob
```

## Bob adds Alice

```text
/add alice
```

## Alice sends a message

```text
/send bob hello
```

## Bob replies

```text
/send alice hi
```

Successful output on Alice’s terminal may look like:

```text
added contact bob
bob: hi
sent encrypted message to bob
```

The first successful long-distance exchange confirmed that:

* Both clients could reach the relay.
* Public-key lookup worked.
* Alice could encrypt a message for Bob.
* The relay could route the encrypted envelope.
* Bob could decrypt Alice’s message.
* Bob could reply through the same system.
* The server did not need access to the plaintext.

---

# CLI Commands

```text
/add <username>             Add or refresh a contact
/contacts                   List saved contacts
/send <username> <message>  Send an encrypted message
/quit                       Exit the client
```

Every outgoing message currently requires the `/send` command.

This works:

```text
/send bob okay, let us talk
```

Typing ordinary text without `/send` produces:

```text
unknown command. type /help.
```

---

# Daily Startup

After the initial installation, neither user needs to rebuild the project unless the code changes.

## Relay host

### 1. Connect Tailscale

Confirm that Tailscale is connected.

### 2. Start the server

```sh
cd /path/to/phantasma

PHANTASMA_BIND_ADDR=100.x.x.x:3000 \
PHANTASMA_DATABASE_URL=sqlite://phantasma.sqlite \
./target/debug/server
```

### 3. Start Alice

In another terminal:

```sh
cd /path/to/phantasma

./target/debug/client \
  --username alice \
  --server http://100.x.x.x:3000
```

## Remote Windows user

### 1. Connect Tailscale

### 2. Start Bob

```powershell
cd C:\Users\<USER>\Documents\phantasma

.\target\debug\client.exe `
  --username bob `
  --server http://100.x.x.x:3000
```

The existing identities and contacts load automatically.

Users do not normally need to run `/add` again unless a contact is missing or the contact’s key changed.

---

# Stopping Phantasma

Each client exits with:

```text
/quit
```

The relay host stops the server with:

```text
Ctrl+C
```

If the relay stops, clients cannot exchange or queue new messages until it starts again.

---

# Offline Messages

The relay uses SQLite to queue encrypted messages for users who are temporarily offline.

To test offline delivery:

1. Keep the relay running.
2. Close Bob with `/quit`.
3. Alice sends:

```text
/send bob this was sent while you were offline
```

4. Bob reconnects using the same identity.
5. The relay delivers the queued encrypted envelope.
6. Bob decrypts the message locally.

The relay stores ciphertext, not plaintext.

---

# Local Data

The command-line client stores identities and contacts under:

```text
~/.phantasma
```

Example identity path on macOS:

```text
~/.phantasma/identities/alice.json
```

On Windows, the directory is located under the user’s home directory.

Private keys remain local to the user’s device.

Deleting an identity file destroys that local identity. Messages encrypted for the deleted private key may no longer be decryptable.

Do not copy another user’s identity file or commit identity files to Git.

---

# SQLite Data

The relay database is configured through:

```text
PHANTASMA_DATABASE_URL
```

Example:

```text
sqlite://phantasma.sqlite
```

The SQLite database supports:

* Public-key directory records
* Encrypted message queueing
* Persistent relay data across restarts

The database should not contain message plaintext under the intended protocol flow.

---

# Optional Browser Client

The `docs/` directory contains a static browser client.

Run it locally with:

```sh
python3 -m http.server 8080 -d docs
```

Then open:

```text
http://127.0.0.1:8080
```

The browser client expects a reachable relay.

For local development:

```text
http://127.0.0.1:3000
```

For a remote relay, update the configured relay URL in `docs/app.js`.

GitHub Pages can host only the static browser files. It cannot host the Rust relay server or maintain long-running WebSocket server connections.

The terminal-to-terminal configuration described above does not require the browser client or GitHub Pages.

---

# Public Deployment

Tailscale is useful for a small private group, but it requires each participant to join the same private network.

A public deployment would instead place the relay on a server with:

* A stable hostname
* HTTPS
* Secure WebSockets using `wss://`
* Firewall configuration
* Process supervision
* Database backups
* Rate limiting
* Authentication protections
* Logging that avoids sensitive data
* A reverse proxy such as Caddy

The Oracle Cloud deployment path is documented in:

```text
deploy/oracle-cloud.md
```

For a reverse-proxied public deployment, the Rust relay can remain bound to:

```text
127.0.0.1:3000
```

Caddy can then handle public HTTPS and `wss://` traffic.

---

# Security Limitations

Phantasma is an educational project and has not undergone an independent security audit.

Areas that require further work before treating it as a production messenger include:

* Public-key fingerprint verification
* Protection against silent key replacement
* Username ownership and authentication
* Contact key-change warnings
* Replay protection
* Message ordering
* Forward secrecy
* Key rotation
* Device revocation
* Multi-device identities
* Metadata minimization
* Abuse prevention
* Rate limiting
* Secure update distribution
* Formal protocol review
* Dependency and implementation auditing

End-to-end encryption protects message contents only when the correct public keys are being used. A future version should let users compare identity fingerprints through a separate trusted channel.

---

# Troubleshooting

## `feature edition2024 is required`

Update Rust:

```sh
rustup update stable
rustup default stable
```

Then verify:

```sh
rustc --version
cargo --version
```

Use Rust and Cargo 1.85 or newer.

## `TcpTestSucceeded : False`

Check:

* Tailscale is connected on both devices.
* Both computers appear under Tailscale **Machines**.
* The relay terminal is still running.
* The relay is listening on the host’s Tailscale IP or `0.0.0.0`.
* Port `3000` is correct.
* macOS allowed incoming connections.
* The relay host’s Mac is awake.
* The correct Tailscale IP was used.

## `connection refused`

The relay is not running, is bound only to `127.0.0.1`, or is listening on another port.

## `address already in use`

Find the process using port `3000`.

On macOS:

```sh
lsof -nP -iTCP:3000 -sTCP:LISTEN
```

Stop the old process or use a different port.

## `unknown command`

Outgoing messages require:

```text
/send <username> <message>
```

Plain text by itself is not currently treated as a message.

## Client connects locally but not remotely

A relay bound to:

```text
127.0.0.1:3000
```

is available only to the same computer.

For Tailscale access, bind to:

```text
100.x.x.x:3000
```

or:

```text
0.0.0.0:3000
```

---

# Development Commands

Build everything:

```sh
cargo build --workspace
```

Build only the client:

```sh
cargo build -p client
```

Build only the server:

```sh
cargo build -p server
```

Run all tests:

```sh
cargo test --workspace
```

Run the relay through Cargo:

```sh
cargo run -p server
```

Run a client through Cargo:

```sh
cargo run -p client -- \
  --username alice \
  --server http://127.0.0.1:3000
```

---

# What I Learned

Building Phantasma connected several layers that are often discussed separately:

* Cryptography determines who can read a message.
* Networking determines whether two devices can reach each other.
* WebSockets provide continuous real-time delivery.
* HTTP supports directory and registration operations.
* SQLite allows encrypted messages to survive temporary disconnections.
* Local files preserve long-term user identities.
* Cross-platform tooling introduces version and environment differences.
* A working local application is not automatically a working remote application.
* A relay can coordinate communication without needing access to message plaintext.

The most important practical lesson was that encryption and connectivity are different problems.

Phantasma handled the encrypted message protocol. Tailscale supplied a private route between two computers on different networks. Once both layers were configured, Alice on macOS and Bob on Windows could communicate through the command line.

---

# Status

Working:

* Rust relay server
* Rust terminal client
* Local identity generation
* Persistent local identities
* Public-key registration
* Contact lookup
* X25519 key agreement
* HKDF-SHA256 key derivation
* XChaCha20-Poly1305 encryption
* WebSocket delivery
* SQLite offline queueing
* Local terminal-to-terminal messaging
* Long-distance terminal messaging over Tailscale
* macOS relay and client
* Windows remote client

Experimental:

* Browser client
* GitHub Pages deployment
* Public relay deployment
* Identity verification workflow
* Production security hardening
