# Interlok PGP

A collection of services that provide GPG/PGP encryption, decryption,
signing, and verification. It uses BouncyCastle to do the heavy lifting.

## PGP Encrypt

This service provides a way to encrypt messages with GPG/PGP. It
requires a public key or the intended recipient, and a message to
encrypt. Optionally it will ASCII armor encode the cipher text
(default), and include extra integrity checks (default).

````xml
    <pgp-encrypt>
        <unique-id>mad-lalande</unique-id>
        <public-key class="constant-data-input-parameter">
            <value>-----BEGIN PGP PUBLIC KEY BLOCK-----

    mQENBF2ckxABCAC5Kfu39ky3OIXkxwWOJx70G2dLRYvDMHXf3ZraUPNRMIhh3ZGx
    -----END PGP PUBLIC KEY BLOCK-----</value>
        </public-key>
        <clear-text class="stream-payload-input-parameter"/>             <!-- clear text comes from message payload -->
        <cipher-text class="stream-payload-output-parameter"/>           <!-- cipher text goes back into the message payload -->
        <armor-encoding>true</armor-encoding>
        <integrity-check>true</integrity-check>
    </pgp-encrypt>
````

## PGP Decrypt

This service provides a way to decrypt GPG/PGP encrypted messages. It
requires a private key, the passphrase to unlock the key, and an
encrypted message.

````xml
    <pgp-decrypt>
        <unique-id>trusting-mayer</unique-id>
        <private-key class="constant-data-input-parameter">
            <value>-----BEGIN PGP PRIVATE KEY BLOCK-----

    lQPGBF2ckxABCAC5Kfu39ky3OIXkxwWOJx70G2dLRYvDMHXf3ZraUPNRMIhh3ZGx
    -----END PGP PRIVATE KEY BLOCK-----</value>
        </private-key>
        <passphrase class="constant-data-input-parameter">
            <value>my5ecr3tP455w0rd</value>
        </passphrase>
        <cipher-text class="stream-payload-input-parameter"/>            <!-- cipher text comes from message payload -->
        <clear-text class="stream-payload-output-parameter"/>            <!-- clear text goes back into the message payload -->
    </pgp-decrypt>
````

## PGP Sign

This service provides a way to sign messages via GPG/PGP. It requires a
private key, the passphrase to unlock the key, and a message to sign.
Optionally it will ASCII armor encode the signature (default) and create
a detached signature (default).

````xml
    <pgp-sign>
        <unique-id>nostalgic-golick</unique-id>
        <private-key class="constant-data-input-parameter">
            <value>-----BEGIN PGP PRIVATE KEY BLOCK-----

    lQPGBF2ckxABCAC5Kfu39ky3OIXkxwWOJx70G2dLRYvDMHXf3ZraUPNRMIhh3ZGx
    -----END PGP PRIVATE KEY BLOCK-----</value>
        </private-key>
        <passphrase class="constant-data-input-parameter">
            <value>my5ecr3tP455w0rd</value>
        </passphrase>
        <clearText class="stream-payload-input-parameter"/>              <!-- clear text comes from message payload -->
        <armor-encoding>true</armor-encoding>
        <detached-signature>true</detached-signature>
        <signature class="metadata-stream-output-parameter">             <!-- detached signature goes into message metadata -->
            <metadata-key>signature</metadata-key>
        </signature>
    </pgp-sign>
````

## PGP Verify

This service provides a way to verify GPG/PGP signed messages. It
requires the public key of whom signed the message, the signed message,
and (if the signature is detached) the signature. It will will also
optionally return the original/unsigned message (especially useful if
the signature was not detached).

````xml
    <pgp-verify>
        <unique-id>jovial-elion</unique-id>
        <public-key class="constant-data-input-parameter">
            <value>-----BEGIN PGP PUBLIC KEY BLOCK-----

    mQENBF2ckxABCAC5Kfu39ky3OIXkxwWOJx70G2dLRYvDMHXf3ZraUPNRMIhh3ZGx
    -----END PGP PUBLIC KEY BLOCK-----</value>
        </public-key>
        <signed-message class="stream-payload-input-parameter"/>         <!-- signed message (without signature, as it's detached) -->
        <signature class="metadata-stream-input-parameter">              <!-- detached signature comes into message metadata -->
            <metadata-key>signature</metadata-key>
        </signature>
        <original-message class="string-payload-data-output-parameter"/> <!-- optional original message, without signature -->
    </pgp-verify>
````
