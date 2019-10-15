package com.adaptris.security.pgp;

import com.adaptris.annotation.AdapterComponent;
import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldDefault;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.ServiceException;
import com.adaptris.core.common.MetadataStreamInputParameter;
import com.adaptris.core.common.PayloadStreamInputParameter;
import com.adaptris.core.common.PayloadStreamOutputParameter;
import com.adaptris.interlok.config.DataInputParameter;
import com.adaptris.interlok.config.DataOutputParameter;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import org.apache.commons.lang.BooleanUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

/**
 * This service provides a way to encrypt messages with GPG/PGP. It
 * requires a public key or the intended recipient, and a message to
 * encrypt. Optionally it will ASCII armor encode the cipher text
 * (default), and include extra integrity checks (default).
 *
 * <pre>{@code
 *    <pgp-encrypt>
 *        <unique-id>mad-lalande</unique-id>
 *        <public-key class="constant-data-input-parameter">
 *            <value>-----BEGIN PGP PUBLIC KEY BLOCK-----
 *
 *    mQENBF2ckxABCAC5Kfu39ky3OIXkxwWOJx70G2dLRYvDMHXf3ZraUPNRMIhh3ZGx
 *    -----END PGP PUBLIC KEY BLOCK-----</value>
 *        </public-key>
 *        <clear-text class="stream-payload-input-parameter"/>             <!-- clear text comes from message payload -->
 *        <cipher-text class="stream-payload-output-parameter"/>           <!-- cipher text goes back into the message payload -->
 *        <armor-encoding>true</armor-encoding>
 *        <integrity-check>true</integrity-check>
 *    </pgp-encrypt>
 * }</pre>
 *
 * @author aanderson
 * @config pgp-encrypt
 */
@XStreamAlias("pgp-encrypt")
@AdapterComponent
@ComponentProfile(summary = "Encrypt data using a PGP/GPG public key", tag = "pgp,gpg,encrypt,public key", since="3.9.2")
@DisplayOrder(order = { "publicKey", "clearText", "cipherText" })
public class PGPEncryptService extends PGPService
{
	private static transient Logger log = LoggerFactory.getLogger(PGPEncryptService.class);

	@NotNull
	@Valid
	private DataInputParameter publicKey = new MetadataStreamInputParameter();

	@NotNull
	@Valid
	private DataInputParameter clearText = new PayloadStreamInputParameter();

	@NotNull
	@Valid
	private DataOutputParameter cipherText = new PayloadStreamOutputParameter();

	@Valid
	@AdvancedConfig
	@InputFieldDefault(value = "true")
	private Boolean armorEncoding = true;

	@Valid
	@AdvancedConfig
	@InputFieldDefault(value = "true")
	private Boolean integrityCheck = true;

	/**
	 * {@inheritDoc}.
	 */
	@Override
	public void doService(AdaptrisMessage message) throws ServiceException
	{
		try
		{
			InputStream key = extractStream(message, publicKey, "Could not read public key");
			InputStream clear = extractStream(message, clearText, "Could not read clear text message to encrypt");
			ByteArrayOutputStream cipher = new ByteArrayOutputStream();
			encrypt(clear, cipher, key, armorEncoding, integrityCheck);
			insertStream(message, cipherText, cipher);
		}
		catch (Exception e)
		{
			log.error("An error occurred during PGP encryption", e);
			throw new ServiceException(e);
		}
	}

	/**
	 * Set the public key for encryption.
	 *
	 * @param publicKey The public key.
	 */
	public void setPublicKey(DataInputParameter publicKey)
	{
		this.publicKey = publicKey;
	}

	/**
	 * Get the pubilc key for encryption.
	 *
	 * @return The public key.
	 */
	public DataInputParameter getPublicKey()
	{
		return publicKey;
	}

	/**
	 * Set the clear text to encrypt.
	 *
	 * @param clearText The clear text.
	 */
	public void setClearText(DataInputParameter clearText)
	{
		this.clearText = clearText;
	}

	/**
	 * Get the clear text to encrypt.
	 *
	 * @return The clear text.
	 */
	public DataInputParameter getClearText()
	{
		return clearText;
	}

	/**
	 * Set the encrypted cipher text.
	 *
	 * @param cipherText The cipher text.
	 */
	public void setCipherText(DataOutputParameter cipherText)
	{
		this.cipherText = cipherText;
	}

	/**
	 * Get the encrypted cipher text.
	 *
	 * @return The cipher text.
	 */
	public DataOutputParameter getCipherText()
	{
		return cipherText;
	}

	/**
	 * Set whether the cipher text output should be ASCII armor encoded.
	 *
	 * @param armorEncoding Whether the cipher text should be armor encoded.
	 */
	public void setArmorEncoding(Boolean armorEncoding)
	{
		this.armorEncoding = BooleanUtils.toBooleanDefaultIfNull(armorEncoding, true);
	}

	/**
	 * Get whether the cipher text output should be ASCII armor encoded.
	 *
	 * @return Whether the cipher text should be armor encoded.
	 */
	public Boolean getArmorEncoding()
	{
		return armorEncoding;
	}

	/**
	 * Set whether there should be integrity checks within the cipher text.
	 *
	 * @param integrityCheck Whether there should be integrity checks in the cipher text.
	 */
	public void setIntegrityCheck(Boolean integrityCheck)
	{
		this.integrityCheck = BooleanUtils.toBooleanDefaultIfNull(integrityCheck, true);
	}

	/**
	 * Get whether there should be integrity checks within the cipher text.
	 *
	 * @return Whether there should be integrity checks in the cipher text.
	 */
	public Boolean getIntegrityCheck()
	{
		return integrityCheck;
	}

	/**
	 * Encrypt data using a GPG public key.
	 *
	 * @param in                 The data to encrypt.
	 * @param out                The encrypted data.
	 * @param encKey             The public key.
	 * @param armor              Whether to armor encode.
	 * @param withIntegrityCheck Whether to include integrity check.
	 * @throws PGPException Thrown if there's a problem with the key/passphrase.
	 * @throws IOException  Thrown if there's an IO issue.
	 */
	private static void encrypt(InputStream in, OutputStream out, InputStream encKey, boolean armor, boolean withIntegrityCheck) throws PGPException, IOException
	{
		if (armor)
		{
			out = new ArmoredOutputStream(out);
		}
		/* TODO cipher could be an advanced option */
		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));
		cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(readPublicKey(encKey)).setProvider("BC"));
		OutputStream cOut = cPk.open(out, new byte[1 << 16]);
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
		writeFileToLiteralData(in, comData.open(cOut), PGPLiteralData.BINARY, new byte[1 << 16]);
		comData.close();
		cOut.close();
		if (armor)
		{
			out.close();
		}
	}

	/**
	 * A simple routine that opens a key ring file and loads the first available key
	 * suitable for encryption.
	 *
	 * @param input data stream containing the public key data
	 * @return the first public key found.
	 * @throws IOException
	 * @throws PGPException
	 */
	private static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException
	{
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(getDecoderStream(input), new JcaKeyFingerprintCalculator());
		//
		// we just loop through the collection till we find a key suitable for encryption, in the real
		// world you would probably want to be a bit smarter about this.
		//
		Iterator keyRingIter = pgpPub.getKeyRings();
		while (keyRingIter.hasNext())
		{
			PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();
			Iterator keyIter = keyRing.getPublicKeys();
			while (keyIter.hasNext())
			{
				PGPPublicKey key = (PGPPublicKey)keyIter.next();
				if (key.isEncryptionKey())
				{
					return key;
				}
			}
		}
		throw new IllegalArgumentException("Can't find encryption key in key ring");
	}

	/**
	 * Write out the contents of the provided file as a literal data packet in partial packet
	 * format.
	 *
	 * @param in       the stream to read the data from.
	 * @param out      the stream to write the literal data to.
	 * @param fileType the {@link PGPLiteralData} type to use for the file data.
	 * @param buffer   buffer to be used to chunk the file into partial packets.
	 * @throws IOException if an error occurs reading the file or writing to the output stream.
	 * @see PGPLiteralDataGenerator#open(OutputStream, char, String, Date, byte[])
	 */
	private static void writeFileToLiteralData(InputStream in, OutputStream out, char fileType, byte[] buffer) throws IOException
	{
		PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
		OutputStream pOut = lData.open(out, fileType, in.toString(), new Date(), buffer);
		byte[] buf = new byte[buffer.length];
		try
		{
			int len;
			while ((len = in.read(buf)) > 0)
			{
				pOut.write(buf, 0, len);
			}
			pOut.close();
		}
		finally
		{
			Arrays.fill(buf, (byte)0);
			try
			{
				in.close();
			}
			catch (IOException ignored)
			{
				// ignore...
			}
		}
	}
}
