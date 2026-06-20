# Security Policy

Phantasma is a learning project. It has not had an independent security audit, and it should not be treated as a production replacement for a mature encrypted messenger.

## Supported Versions

Security notes apply to the current `main` branch.

## Known Limitations

The current implementation intentionally keeps the server as a relay for public keys and encrypted message bytes, but several security features are still missing:

* No public-key fingerprint verification.
* No protection against silent public-key replacement by the relay or by a compromised account flow.
* No username ownership or authentication beyond registering a public key under a name.
* No replay protection.
* No forward secrecy.
* No key rotation or device revocation.
* No multi-device identity model.
* No formal message ordering guarantees.
* No metadata minimization beyond encrypting message contents.
* No production abuse prevention or rate limiting.
* No independent protocol review.

End-to-end encryption protects message contents only when clients use the intended public keys. A safer version should let users compare identity fingerprints through a separate trusted channel before relying on a contact key.

## Reporting Issues

If you find a security issue, report it privately if possible before publishing details. Include:

* The affected command, endpoint, or protocol flow.
* Steps to reproduce the issue.
* Whether the issue can expose plaintext, private keys, message metadata, or queued ciphertext.

Do not use this project for sensitive production communication.
