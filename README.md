# Interlok PGP

A collection of services that provide GPG/PGP encryption, decryption,
signing, and verification. It uses BouncyCastle to do the heavy lifting.

## PGP Encrypt

This service provides a way to encrypt messages with GPG/PGP. It
requires a public key or the intended recipient, and a message to
encrypt. Optionally it will ASCII armor encode the cipher text
(default), and include extra integrity checks (default).

## PGP Decrypt

This service provides a way to verify GPG/PGP signed messages. It
requires the public key of whom signed the message, the signed message,
and (if the signature is detached) the signature. It will will also
optionally return the original/unsigned message (especially useful if
the signature was not detached).

## PGP Sign

This service provides a way to sign messages via GPG/PGP. It requires a
private key, the passphrase to unlock the key, and a message to sign.
Optionally it will ASCII armor encode the signature (default) and create
a detached signature (default).

## PGP Verify

This service provides a way to decrypt GPG/PGP encrypted messages.  It
requires a private key, the passphrase to unlock the key, and an
encrypted message.
