package com.adaptris.security.pgp;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.util.Iterator;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import com.adaptris.annotation.AdapterComponent;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.ServiceException;
import com.adaptris.interlok.config.DataInputParameter;
import com.adaptris.interlok.config.DataOutputParameter;
import com.adaptris.interlok.resolver.ExternalResolver;
import com.adaptris.security.password.Password;
import com.thoughtworks.xstream.annotations.XStreamAlias;

/**
 * This service provides a way to decrypt GPG/PGP encrypted messages.
 * It requires a private key, the passphrase to unlock the key, and
 * an encrypted message.
 *
 * <pre>{@code
 *    <pgp-decrypt>
 *        <unique-id>trusting-mayer</unique-id>
 *        <private-key class="constant-data-input-parameter">
 *            <value>-----BEGIN PGP PRIVATE KEY BLOCK-----
 *
 *    lQPGBF2ckxABCAC5Kfu39ky3OIXkxwWOJx70G2dLRYvDMHXf3ZraUPNRMIhh3ZGx
 *    -----END PGP PRIVATE KEY BLOCK-----</value>
 *        </private-key>
 *        <passphrase class="constant-data-input-parameter">
 *            <value>my5ecr3tP455w0rd</value>
 *        </passphrase>
 *        <cipher-text class="stream-payload-input-parameter"/>            <!-- cipher text comes from message payload -->
 *        <clear-text class="stream-payload-output-parameter"/>            <!-- clear text goes back into the message payload -->
 *    </pgp-decrypt>
 * }</pre>
 *
 * @author aanderson
 * @config pgp-decrypt
 */
@XStreamAlias("pgp-decrypt")
@AdapterComponent
@ComponentProfile(summary = "Decrypt data using a PGP/GPG private key", tag = "pgp,gpg,decrypt,private key", since = "3.9.2")
@DisplayOrder(order = { "privateKey", "passphrase", "clearText", "clearText" })
public class PGPDecryptService extends PGPService {
  @NotNull
  @Valid
  private DataInputParameter<?> privateKey;

  @NotNull
  @Valid
  private DataInputParameter<?> passphrase;

  @NotNull
  @Valid
  private DataInputParameter<?> cipherText;

  @NotNull
  @Valid
  private DataOutputParameter<?> clearText;

  /**
   * {@inheritDoc}.
   */
  @Override
  public void doService(AdaptrisMessage message) throws ServiceException {
    try {
      InputStream key = extractStream(message, privateKey, "Could not read private key");
      String password = Password.decode(ExternalResolver.resolve(extractString(message, passphrase, "Could not read passphrase")));
      InputStream cipher = extractStream(message, cipherText, "Could not read cipher text message to decrypt");
      ByteArrayOutputStream clear = new ByteArrayOutputStream();
      decrypt(cipher, key, password.toCharArray(), clear);
      insertStream(message, clearText, clear);
    } catch (Exception e) {
      log.error("An error occurred during PGP decryption", e);
      throw new ServiceException(e);
    }
  }

  /**
   * Set the private key for decryption.
   *
   * @param privateKey
   *          The private key.
   */
  public void setPrivateKey(DataInputParameter<?> privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * Get the private key for decryption.
   *
   * @return The private key.
   */
  public DataInputParameter<?> getPrivateKey() {
    return privateKey;
  }

  /**
   * Set the cipher text to decrypt.
   *
   * @param cipherText
   *          The cipher text.
   */
  public void setCipherText(DataInputParameter<?> cipherText) {
    this.cipherText = cipherText;
  }

  /**
   * Get the cipher text to decrypt.
   *
   * @return The cipher text.
   */
  public DataInputParameter<?> getCipherText() {
    return cipherText;
  }

  /**
   * Set the passphrase to unlock the private key.
   *
   * @param passphrase
   *          The passphrase.
   */
  public void setPassphrase(DataInputParameter<?> passphrase) {
    this.passphrase = passphrase;
  }

  /**
   * Get the passphrase to unlock the private key.
   *
   * @return The passphrase.
   */
  public DataInputParameter<?> getPassphrase() {
    return passphrase;
  }

  /**
   * Set the decrypted clear text.
   *
   * @param clearText
   *          The clear text.
   */
  public void setClearText(DataOutputParameter<?> clearText) {
    this.clearText = clearText;
  }

  /**
   * Get the decrypted clear text.
   *
   * @return The clear text.
   */
  public DataOutputParameter<?> getClearText() {
    return clearText;
  }

  /**
   * Decrypt a GPG encrypted message.
   *
   * @param in
   *          The encrypted data.
   * @param key
   *          The private key.
   * @param passwd
   *          The passphrase to unlock the key.
   * @param out
   *          The decrypted data.
   * @throws PGPException
   *           Thrown if there's a problem with the key/passphrase.
   * @throws IOException
   *           Thrown if there's an IO issue.
   */
  private void decrypt(InputStream in, InputStream key, char[] passwd, OutputStream out) throws PGPException, IOException {
    in = getDecoderStream(in);
    JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
    PGPEncryptedDataList enc;
    Object o = pgpF.nextObject();
    //
    // the first object might be a PGP marker packet.
    //
    if (o instanceof PGPEncryptedDataList) {
      enc = (PGPEncryptedDataList) o;
    } else {
      enc = (PGPEncryptedDataList) pgpF.nextObject();
    }
    //
    // find the secret key
    //
    Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
    PGPPrivateKey sKey = null;
    PGPPublicKeyEncryptedData pbe = null;
    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(getDecoderStream(key), new JcaKeyFingerprintCalculator());
    while (sKey == null && it.hasNext()) {
      pbe = (PGPPublicKeyEncryptedData) it.next();
      sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
    }
    if (sKey == null) {
      throw new IllegalArgumentException("Secret key for message not found");
    }
    InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(PROVIDER).build(sKey));
    JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
    PGPCompressedData cData = (PGPCompressedData) plainFact.nextObject();
    try (InputStream compressedStream = new BufferedInputStream(cData.getDataStream())) {
      JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedStream);
      Object message = pgpFact.nextObject();
      if (message instanceof PGPLiteralData) {
        PGPLiteralData ld = (PGPLiteralData) message;
        InputStream unc = ld.getInputStream();
        OutputStream fOut = new BufferedOutputStream(out);
        Streams.pipeAll(unc, fOut);
        fOut.close();
      } else if (message instanceof PGPOnePassSignatureList) {
        throw new PGPException("Encrypted message contains a signed message - not literal data");
      } else {
        throw new PGPException("Message is not a simple encrypted file - type unknown");
      }
    }
    if (pbe.isIntegrityProtected()) {
      if (!pbe.verify()) {
        log.warn("Message failed integrity check");
      } else {
        log.debug("Message integrity check passed");
      }
    } else {
      log.debug("No message integrity check");
    }
  }

  /**
   * Search a secret key ring collection for a secret key corresponding to keyID if it exists.
   *
   * @param pgpSec
   *          a secret key ring collection.
   * @param keyID
   *          keyID we want.
   * @param pass
   *          passphrase to decrypt secret key with.
   * @return the private key.
   * @throws PGPException
   * @throws NoSuchProviderException
   */
  private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException {
    PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
    if (pgpSecKey == null) {
      return null;
    }
    return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(PROVIDER).build(pass));
  }
  
}
