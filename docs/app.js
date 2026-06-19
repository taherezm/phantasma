import sodium from "https://cdn.jsdelivr.net/npm/libsodium-wrappers-sumo@0.8.4/+esm";

// Edit this when deploying to GitHub Pages. Use https:// for hosted relays so
// the browser connects with wss:// for WebSocket delivery.
const DEFAULT_RELAY_URL = "http://127.0.0.1:3000";

const MESSAGE_VERSION = 1;
const KEY_DERIVATION_SALT = "phantasma x25519 xchacha20poly1305 v1";
const ASSOCIATED_DATA_PREFIX = "phantasma:v1:";
const STORAGE_PREFIX = "phantasma.web";
const USERNAME_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const elements = {
  username: document.querySelector("#username"),
  relayUrl: document.querySelector("#relay-url"),
  start: document.querySelector("#start"),
  contactName: document.querySelector("#contact-name"),
  addContact: document.querySelector("#add-contact"),
  recipient: document.querySelector("#recipient"),
  status: document.querySelector("#status"),
  messages: document.querySelector("#messages"),
  sendForm: document.querySelector("#send-form"),
  message: document.querySelector("#message"),
};

const state = {
  username: "",
  relay: null,
  identity: null,
  contacts: new Map(),
  socket: null,
  reconnectTimer: null,
  started: false,
};

elements.relayUrl.value = localStorage.getItem(`${STORAGE_PREFIX}.relayUrl`) || DEFAULT_RELAY_URL;
elements.username.value = localStorage.getItem(`${STORAGE_PREFIX}.lastUsername`) || "";
setControlsEnabled(false);

await sodium.ready;
setStatus("Ready.");

elements.start.addEventListener("click", () => start().catch(showError));
elements.addContact.addEventListener("click", () => addContactFromInput().catch(showError));
elements.sendForm.addEventListener("submit", (event) => {
  event.preventDefault();
  sendCurrentMessage().catch(showError);
});

async function start() {
  const username = elements.username.value.trim();
  const relayUrl = elements.relayUrl.value.trim();

  if (!USERNAME_PATTERN.test(username)) {
    throw new Error("Username can use letters, numbers, '.', '-', and '_'.");
  }

  state.relay = makeRelayConfig(relayUrl, username);
  state.username = username;
  state.identity = loadOrCreateIdentity(username);
  state.contacts = loadContacts(username);
  state.started = true;

  localStorage.setItem(`${STORAGE_PREFIX}.lastUsername`, username);
  localStorage.setItem(`${STORAGE_PREFIX}.relayUrl`, relayUrl);

  await registerPublicKey();
  refreshContacts();
  connectWebSocket();
  setControlsEnabled(true);
  setStatus(`Signed in as ${username}.`);
}

async function registerPublicKey() {
  const body = {
    username: state.username,
    identity_public_key: state.identity.identityPublicKey,
    encryption_public_key: state.identity.encryptionPublicKey,
  };

  await fetchJson(`${state.relay.httpBaseUrl}/users`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function addContactFromInput() {
  ensureStarted();
  const username = elements.contactName.value.trim();

  if (!USERNAME_PATTERN.test(username)) {
    throw new Error("Contact username can use letters, numbers, '.', '-', and '_'.");
  }

  const contact = await lookupPublicKey(username);

  if (!contact) {
    setStatus(`No public key found for ${username}.`);
    return;
  }

  state.contacts.set(contact.username, contact);
  saveContacts();
  refreshContacts();
  elements.contactName.value = "";
  setStatus(`Added ${contact.username}.`);
}

async function sendCurrentMessage() {
  ensureStarted();
  const recipient = elements.recipient.value;
  const body = elements.message.value.trim();

  if (!recipient) {
    throw new Error("Add a contact first.");
  }

  if (!body) {
    return;
  }

  let contact = state.contacts.get(recipient);

  if (!contact) {
    contact = await lookupPublicKey(recipient);

    if (!contact) {
      throw new Error(`No public key found for ${recipient}.`);
    }

    state.contacts.set(contact.username, contact);
    saveContacts();
    refreshContacts();
  }

  const encrypted = await encryptMessage(state.username, recipient, body, contact.encryption_public_key);
  const routed = {
    from: state.username,
    to: recipient,
    encrypted,
  };
  const bytes = encoder.encode(JSON.stringify(routed));

  if (!state.socket || state.socket.readyState !== WebSocket.OPEN) {
    throw new Error("Not connected to the relay.");
  }

  state.socket.send(bytes);
  addMessage(state.username, body);
  elements.message.value = "";
  setStatus(`Sent encrypted message to ${recipient}.`);
}

async function receiveEncryptedBytes(bytes) {
  const encrypted = JSON.parse(decoder.decode(bytes));
  const plaintext = await decryptMessage(encrypted);

  if (plaintext.to !== state.username) {
    return;
  }

  const contact = await findOrAddContact(plaintext.from);

  if (contact.encryption_public_key !== encrypted.sender_encryption_public_key) {
    throw new Error(`Discarded message from ${plaintext.from}; sender key changed.`);
  }

  addMessage(plaintext.from, plaintext.body);
}

async function findOrAddContact(username) {
  const existing = state.contacts.get(username);

  if (existing) {
    return existing;
  }

  const contact = await lookupPublicKey(username);

  if (!contact) {
    throw new Error(`No public key found for ${username}.`);
  }

  state.contacts.set(contact.username, contact);
  saveContacts();
  refreshContacts();
  setStatus(`Added ${contact.username}.`);

  return contact;
}

async function encryptMessage(from, to, body, recipientPublicKeyText) {
  const senderPublicKey = fromBase64(state.identity.encryptionPublicKey);
  const recipientPublicKey = fromBase64(recipientPublicKeyText);
  const sharedSecret = sodium.crypto_scalarmult(state.identity.encryptionSecretKey, recipientPublicKey);
  const messageKey = await deriveMessageKey(sharedSecret, senderPublicKey, recipientPublicKey);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const plaintext = encoder.encode(JSON.stringify({ from, to, body }));
  const aad = associatedData(senderPublicKey, recipientPublicKey);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    messageKey,
  );

  return {
    version: MESSAGE_VERSION,
    sender_encryption_public_key: state.identity.encryptionPublicKey,
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
  };
}

async function decryptMessage(encrypted) {
  if (encrypted.version !== MESSAGE_VERSION) {
    throw new Error("Unsupported encrypted message version.");
  }

  const senderPublicKey = fromBase64(encrypted.sender_encryption_public_key);
  const recipientPublicKey = fromBase64(state.identity.encryptionPublicKey);
  const sharedSecret = sodium.crypto_scalarmult(state.identity.encryptionSecretKey, senderPublicKey);
  const messageKey = await deriveMessageKey(sharedSecret, senderPublicKey, recipientPublicKey);
  const nonce = fromBase64(encrypted.nonce);
  const ciphertext = fromBase64(encrypted.ciphertext);
  const aad = associatedData(senderPublicKey, recipientPublicKey);
  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    messageKey,
  );

  return JSON.parse(decoder.decode(plaintext));
}

async function deriveMessageKey(sharedSecret, senderPublicKey, recipientPublicKey) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(KEY_DERIVATION_SALT),
      info: associatedData(senderPublicKey, recipientPublicKey),
    },
    keyMaterial,
    256,
  );

  return new Uint8Array(bits);
}

function associatedData(senderPublicKey, recipientPublicKey) {
  return concatBytes(encoder.encode(ASSOCIATED_DATA_PREFIX), senderPublicKey, recipientPublicKey);
}

function connectWebSocket() {
  clearTimeout(state.reconnectTimer);

  if (state.socket) {
    state.socket.close();
  }

  const socket = new WebSocket(state.relay.webSocketUrl);
  socket.binaryType = "arraybuffer";
  state.socket = socket;
  setStatus(`Connecting to ${state.relay.webSocketUrl}`);

  socket.addEventListener("open", () => {
    setStatus("Connected.");
  });

  socket.addEventListener("message", (event) => {
    const read = event.data instanceof Blob ? event.data.arrayBuffer() : Promise.resolve(event.data);
    read
      .then((buffer) => receiveEncryptedBytes(new Uint8Array(buffer)))
      .catch(showError);
  });

  socket.addEventListener("close", () => {
    if (!state.started) {
      return;
    }

    setStatus("Disconnected. Reconnecting in 2 seconds.");
    state.reconnectTimer = setTimeout(connectWebSocket, 2000);
  });

  socket.addEventListener("error", () => {
    setStatus("WebSocket error.");
  });
}

function loadOrCreateIdentity(username) {
  const key = `${STORAGE_PREFIX}.identity.${username}`;
  const existing = localStorage.getItem(key);

  if (existing) {
    const parsed = JSON.parse(existing);

    return {
      identityPublicKey: parsed.identityPublicKey,
      identitySecretKey: fromBase64(parsed.identitySecretKey),
      encryptionPublicKey: parsed.encryptionPublicKey,
      encryptionSecretKey: fromBase64(parsed.encryptionSecretKey),
    };
  }

  const identityPair = sodium.crypto_sign_keypair();
  const encryptionPair = sodium.crypto_box_keypair();
  const identity = {
    identityPublicKey: toBase64(identityPair.publicKey),
    identitySecretKey: toBase64(identityPair.privateKey),
    encryptionPublicKey: toBase64(encryptionPair.publicKey),
    encryptionSecretKey: toBase64(encryptionPair.privateKey),
  };

  localStorage.setItem(key, JSON.stringify(identity));

  return {
    identityPublicKey: identity.identityPublicKey,
    identitySecretKey: identityPair.privateKey,
    encryptionPublicKey: identity.encryptionPublicKey,
    encryptionSecretKey: encryptionPair.privateKey,
  };
}

function loadContacts(username) {
  const raw = localStorage.getItem(contactStorageKey(username));

  if (!raw) {
    return new Map();
  }

  const entries = JSON.parse(raw);

  return new Map(entries.map((entry) => [entry.username, entry]));
}

function saveContacts() {
  localStorage.setItem(contactStorageKey(state.username), JSON.stringify([...state.contacts.values()]));
}

function contactStorageKey(username) {
  return `${STORAGE_PREFIX}.contacts.${username}`;
}

function refreshContacts() {
  const selected = elements.recipient.value;
  elements.recipient.innerHTML = "";

  for (const username of [...state.contacts.keys()].sort()) {
    const option = document.createElement("option");
    option.value = username;
    option.textContent = username;
    elements.recipient.append(option);
  }

  if (state.contacts.has(selected)) {
    elements.recipient.value = selected;
  }
}

async function lookupPublicKey(username) {
  const response = await fetch(`${state.relay.httpBaseUrl}/users/${encodeURIComponent(username)}/public-key`);

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    throw new Error(await response.text());
  }

  return response.json();
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);

  if (!response.ok) {
    throw new Error(await response.text());
  }

  return response.json();
}

function makeRelayConfig(rawUrl, username) {
  const url = new URL(rawUrl);
  const isLocal =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";

  if (location.protocol === "https:" && url.protocol !== "https:" && !isLocal) {
    throw new Error("HTTPS pages need an HTTPS relay URL so WebSocket delivery can use wss://.");
  }

  const wsProtocol = url.protocol === "https:" ? "wss:" : "ws:";

  if (location.protocol === "https:" && wsProtocol !== "wss:" && !isLocal) {
    throw new Error("HTTPS pages need wss:// WebSocket delivery.");
  }

  const basePath = url.pathname.replace(/\/$/, "");
  const httpBaseUrl = `${url.protocol}//${url.host}${basePath}`;
  const webSocketUrl = `${wsProtocol}//${url.host}${basePath}/ws/${encodeURIComponent(username)}`;

  return { httpBaseUrl, webSocketUrl };
}

function ensureStarted() {
  if (!state.started) {
    throw new Error("Enter a username and start first.");
  }
}

function setControlsEnabled(enabled) {
  elements.contactName.disabled = !enabled;
  elements.addContact.disabled = !enabled;
  elements.recipient.disabled = !enabled;
  elements.message.disabled = !enabled;
  elements.sendForm.querySelector("button").disabled = !enabled;
}

function setStatus(message) {
  elements.status.textContent = message;
}

function showError(error) {
  setStatus(error.message || String(error));
}

function addMessage(sender, body) {
  const line = document.createElement("p");
  line.className = "message";
  line.textContent = `${sender}: ${body}`;
  elements.messages.append(line);
  elements.messages.scrollTop = elements.messages.scrollHeight;
}

function toBase64(bytes) {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}

function fromBase64(text) {
  return sodium.from_base64(text, sodium.base64_variants.URLSAFE_NO_PADDING);
}

function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;

  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }

  return output;
}
