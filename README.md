# Phantasma

Phantasma is a small end-to-end encrypted messenger for a private group of friends. It is a learning project with one central rule: the relay server never gets the plaintext of a message.

The project has:

- `server`: a Rust relay server using HTTP, WebSocket delivery, and SQLite.
- `client`: a Rust command-line client.
- `shared`: shared Rust message and directory types.
- `docs`: a static browser client for GitHub Pages.

## How It Works

Each client creates keys locally and keeps the private keys on that device. Public keys are registered with the relay under a username. When Alice sends a message to Bob, Alice's client looks up Bob's public encryption key, encrypts the message locally, and sends encrypted bytes to the relay. The relay either forwards those bytes to Bob if he is online or queues them in SQLite until Bob reconnects.

Only the recipient's client can decrypt the message.

## Crypto

The Rust client uses established crates instead of hand-written crypto:

- `x25519-dalek` for X25519 key agreement.
- `chacha20poly1305` for XChaCha20-Poly1305 authenticated encryption.
- `hkdf` and `sha2` for deriving message keys from X25519 shared secrets.
- `ed25519-dalek` for long-term identity keys.

The browser client uses `libsodium.js` for X25519 and XChaCha20-Poly1305, plus WebCrypto HKDF-SHA256 to match the Rust client protocol.

## Run Locally

Start the relay:

```sh
cargo run -p server
```

Run two CLI clients:

```sh
cargo run -p client -- --username alice
cargo run -p client -- --username bob
```

In a client:

```text
/add bob
/send bob hello
```

Run the browser client locally:

```sh
python3 -m http.server 8080 -d docs
```

Then open:

```text
http://127.0.0.1:8080
```

The local browser client expects the relay at:

```text
http://127.0.0.1:3000
```

## GitHub Pages

The browser client is in `docs/` so GitHub Pages can serve it without a build step.

In the GitHub repository settings:

1. Go to Settings.
2. Go to Pages.
3. Set the source to the `main` branch and `/docs` folder.

The Pages site should be:

```text
https://taherezm.github.io/phantasma/
```

GitHub Pages only hosts the static browser client. The Rust relay server still has to run somewhere else.

For a hosted relay, edit this line in `docs/app.js`:

```js
const DEFAULT_RELAY_URL = "https://your-relay.example.com";
```

The browser will use `wss://` for WebSocket delivery when the relay URL starts with `https://`.

## Hosted Relay

GitHub Pages can host only the static browser files. The relay needs to run on a server that supports long-running WebSocket connections.

The Oracle Cloud Always Free VM path is documented here:

```text
deploy/oracle-cloud.md
```

The relay supports these environment variables:

```text
PHANTASMA_BIND_ADDR=127.0.0.1:3000
PHANTASMA_DATABASE_URL=sqlite://phantasma.sqlite
```

For a public deployment, the recommended setup is to keep `PHANTASMA_BIND_ADDR` on `127.0.0.1:3000` and put Caddy in front of it for HTTPS and `wss://` WebSocket traffic.

## Data Stored Locally

The CLI client stores local keys and contacts under:

```text
~/.phantasma
```

The browser client stores keys and contacts in browser `localStorage`.

If local keys are deleted, that identity cannot decrypt old messages.

## Test

```sh
cargo test --workspace
```
