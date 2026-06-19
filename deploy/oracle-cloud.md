# Oracle Cloud Always Free Relay

This is the deployment path for running the Rust relay on an Oracle Cloud Always Free VM while GitHub Pages hosts the browser client from `docs/`.

The relay should stay behind HTTPS. The recommended setup is:

- GitHub Pages serves the web client.
- Oracle Cloud runs the Rust relay.
- Caddy listens on ports 80 and 443, gets HTTPS certificates, and forwards traffic to the relay on `127.0.0.1:3000`.
- The relay stores the public-key directory and queued encrypted messages in SQLite on the VM.

## What I Need Before I Can Deploy It Remotely

To do this from another computer, I need SSH access to the VM:

```text
ssh ubuntu@YOUR_VM_PUBLIC_IP
```

If that command works locally, the remaining setup can be run over SSH.

## Create The VM

In Oracle Cloud:

1. Create an Always Free eligible Ubuntu compute instance in your home region.
2. Assign a public IPv4 address.
3. Save the SSH private key Oracle gives you, or upload your own SSH public key.
4. In the instance network settings, add inbound TCP rules for ports `80` and `443` from `0.0.0.0/0`.
5. Keep port `22` limited to your own IP address when possible.

Do not open port `3000` publicly when using Caddy. The relay can stay private on `127.0.0.1:3000`.

## Point A Domain At The VM

Create a DNS `A` record for a subdomain:

```text
relay.example.com -> YOUR_VM_PUBLIC_IP
```

Use a subdomain, not the GitHub Pages domain. GitHub Pages hosts the web page; this domain points to the relay.

## Install Packages

SSH into the VM, then install the system packages:

```sh
sudo apt update
sudo apt install -y git curl build-essential pkg-config libsqlite3-dev sqlite3
```

Install Rust:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Install Caddy from the official Caddy package repository:

```sh
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
sudo chmod o+r /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
```

## Build The Relay

Clone the repo and build the server:

```sh
cd /home/ubuntu
git clone https://github.com/taherezm/phantasma.git
cd phantasma
cargo build --release -p server
```

Run a quick local check:

```sh
PHANTASMA_BIND_ADDR=127.0.0.1:3000 cargo run -p server
```

In a second SSH window, this should print `Phantasma relay server`:

```sh
curl http://127.0.0.1:3000/
```

Stop the manual server with `Ctrl-C`.

## Install The Relay Service

Copy the example service file:

```sh
sudo cp deploy/phantasma.service.example /etc/systemd/system/phantasma.service
```

Edit it if your username or repo path is different from `/home/ubuntu/phantasma`:

```sh
sudo nano /etc/systemd/system/phantasma.service
```

Start the service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now phantasma
sudo systemctl status phantasma
```

View relay logs:

```sh
journalctl -u phantasma -f
```

## Configure Caddy

Copy the example Caddyfile:

```sh
sudo cp deploy/Caddyfile.example /etc/caddy/Caddyfile
```

Edit the domain:

```sh
sudo nano /etc/caddy/Caddyfile
```

Replace `relay.example.com` with your real relay domain, then reload Caddy:

```sh
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Check the public relay:

```sh
curl https://relay.example.com/
```

## Connect The Web Client

In `docs/app.js`, set the default relay URL:

```js
const DEFAULT_RELAY_URL = "https://relay.example.com";
```

Commit and push that change. GitHub Pages will keep serving the web client, and the browser will use `wss://relay.example.com/ws/<username>` for WebSocket delivery.

## Update The Relay Later

SSH into the VM:

```sh
cd /home/ubuntu/phantasma
git pull
cargo build --release -p server
sudo systemctl restart phantasma
```

## Back Up The SQLite Data

The relay database stores public keys and queued encrypted messages. It does not store plaintext messages, but losing it can lose queued messages.

Back it up with:

```sh
sqlite3 /home/ubuntu/phantasma/phantasma.sqlite ".backup '/home/ubuntu/phantasma/phantasma-backup.sqlite'"
```

## Troubleshooting

If `curl https://relay.example.com/` fails:

- Confirm the domain points to the VM public IP.
- Confirm Oracle inbound rules allow TCP `80` and `443`.
- Confirm Caddy is running with `sudo systemctl status caddy`.
- Confirm the relay is running with `sudo systemctl status phantasma`.
- If ports still look closed, check the VM firewall with `sudo ufw status` and `sudo iptables -S`.

Useful sources:

- Oracle Always Free resources: https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm
- Oracle security rules: https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm
- Caddy install docs: https://caddyserver.com/docs/install
- Rust install docs: https://www.rust-lang.org/tools/install
