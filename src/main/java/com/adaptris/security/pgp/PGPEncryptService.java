package com.adaptris.security.pgp;

import com.adaptris.annotation.AdapterComponent;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.ServiceException;
import com.adaptris.core.ServiceImp;
import com.adaptris.core.common.*;
import com.adaptris.interlok.InterlokException;
import com.adaptris.interlok.config.DataInputParameter;
import com.adaptris.interlok.config.DataOutputParameter;
import com.thoughtworks.xstream.annotations.XStreamAlias;
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
import java.io.*;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

@XStreamAlias("pgp-encryption")
@AdapterComponent
@ComponentProfile(summary = "Encrypt data using a PGP/GPG public key", tag = "pgp,gpg,encrypt,public key")
public class PGPEncryptService extends ServiceImp
{
	private static transient Logger log = LoggerFactory.getLogger(PGPEncryptService.class);

	@NotNull
	@Valid
	private DataInputParameter key = new MetadataStreamInputParameter();

	@NotNull
	@Valid
	private DataInputParameter clearText = new PayloadStreamInputParameter();

	@NotNull
	@Valid
	private DataOutputParameter cipherText = new PayloadStreamOutputParameter();

	/**
	 * {@inheritDoc}.
	 */
	@Override
	public void doService(AdaptrisMessage message) throws ServiceException
	{
		try
		{
			Object key = this.key.extract(message);
			if (key instanceof String)
			{
				key = new ByteArrayInputStream(((String)key).getBytes(message.getContentEncoding()));
			}
			if (!(key instanceof InputStream))
			{
				throw new InterlokException("Could not read public key");
			}
			Object clearText = this.clearText.extract(message);
			if (clearText instanceof String)
			{
				clearText = new ByteArrayInputStream(((String)clearText).getBytes(message.getContentEncoding()));
			}
			if (!(clearText instanceof InputStream))
			{
				throw new InterlokException("Could not read clear text data");
			}

			ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

			encrypt((InputStream)clearText, cipherText, (InputStream)key, true, true);

			try
			{
				this.cipherText.insert(cipherText.toString(message.getContentEncoding()), message);
			}
			catch (InvalidParameterException e)
			{
				/* this.cipherText was not expecting a String, must be an InputStreamWithEncoding */
				this.cipherText.insert(new InputStreamWithEncoding(new ByteArrayInputStream(cipherText.toByteArray()), message.getContentEncoding()), message);
			}
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
	 * @param key The public key.
	 */
	public void setKey(DataInputParameter key)
	{
		this.key = key;
	}

	/**
	 * Get the pubilc key for encryption.
	 *
	 * @return The public key.
	 */
	public DataInputParameter getKey()
	{
		return key;
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
	 * {@inheritDoc}.
	 */
	@Override
	protected void initService()
	{
		/* unused */
	}

	/**
	 * {@inheritDoc}.
	 */
	@Override
	protected void closeService()
	{
		/* unused */
	}

	/**
	 * {@inheritDoc}.
	 */
	@Override
	public void prepare()
	{
		/* unused */
	}

	private static void encrypt(InputStream in, OutputStream out, InputStream encKey, boolean armor, boolean withIntegrityCheck) throws PGPException, IOException
	{
		if (armor)
		{
			out = new ArmoredOutputStream(out);
		}
		try
		{
			PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));
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
		catch (PGPException e)
		{
			log.error("Exception during PGP encryption", e);
			throw e;
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
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
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
		throw new IllegalArgumentException("Can't find encryption key in key ring.");
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
			Arrays.fill(buf, (byte) 0);
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
