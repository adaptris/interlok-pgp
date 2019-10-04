package com.adaptris.security.pgp;

import com.adaptris.annotation.AdapterComponent;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.ServiceException;
import com.adaptris.core.ServiceImp;
import com.adaptris.core.common.InputStreamWithEncoding;
import com.adaptris.core.common.MetadataStreamInputParameter;
import com.adaptris.core.common.PayloadStreamInputParameter;
import com.adaptris.core.common.PayloadStreamOutputParameter;
import com.adaptris.interlok.InterlokException;
import com.adaptris.interlok.config.DataInputParameter;
import com.adaptris.interlok.config.DataOutputParameter;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.io.*;
import java.nio.charset.Charset;
import java.security.InvalidParameterException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;

@XStreamAlias("pgp-decryption")
@AdapterComponent
@ComponentProfile(summary = "Decrypt data using a PGP/GPG private key", tag = "pgp,gpg,decrypt,private key")
public class PGPDecryptService extends ServiceImp
{
	private static transient Logger log = LoggerFactory.getLogger(PGPDecryptService.class);

	private static final Charset CHARSET = Charset.forName("UTF-8");

	static
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	@NotNull
	@Valid
	private DataInputParameter key = new MetadataStreamInputParameter();

	@NotNull
	@Valid
	private DataInputParameter passphrase = new MetadataStreamInputParameter();

	@NotNull
	@Valid
	private DataInputParameter cipherText = new PayloadStreamInputParameter();

	@NotNull
	@Valid
	private DataOutputParameter clearText = new PayloadStreamOutputParameter();

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
				key = new ByteArrayInputStream(((String)key).getBytes(CHARSET));
			}
			if (!(key instanceof InputStream))
			{
				throw new InterlokException("Could not read public key");
			}
			Object passphrase = this.passphrase.extract(message);
			if (passphrase instanceof InputStream)
			{
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				IOUtils.copy((InputStream)passphrase, baos);
				passphrase = baos.toString(CHARSET.toString());
			}
			if (!(passphrase instanceof String))
			{
				throw new InterlokException("Could not read public key");
			}
			Object cipherText = this.cipherText.extract(message);
			if (cipherText instanceof String)
			{
				cipherText = new ByteArrayInputStream(((String)cipherText).getBytes(CHARSET));
			}
			if (!(cipherText instanceof InputStream))
			{
				throw new InterlokException("Could not read cipher text data");
			}

			ByteArrayOutputStream clearText = new ByteArrayOutputStream();

			decrypt((InputStream)cipherText, (InputStream)key, ((String)passphrase).toCharArray(), clearText);

			try
			{
				this.clearText.insert(clearText.toString(CHARSET.toString()), message);
			}
			catch (InvalidParameterException e)
			{
				/* this.clearText was not expecting a String, must be an InputStreamWithEncoding */
				this.clearText.insert(new InputStreamWithEncoding(new ByteArrayInputStream(clearText.toByteArray()), null), message);
			}
		}
		catch (Exception e)
		{
			log.error("An error occurred during PGP decryption", e);
			throw new ServiceException(e);
		}
	}

	/**
	 * Set the private key for decryption.
	 *
	 * @param key The private key.
	 */
	public void setKey(DataInputParameter key)
	{
		this.key = key;
	}

	/**
	 * Get the private key for decryption.
	 *
	 * @return The private key.
	 */
	public DataInputParameter getKey()
	{
		return key;
	}

	/**
	 * Set the cipher text to decrypt.
	 *
	 * @param cipherText The cipher text.
	 */
	public void setCipherText(DataInputParameter cipherText)
	{
		this.cipherText = cipherText;
	}

	/**
	 * Get the cipher text to decrypt.
	 *
	 * @return The cipher text.
	 */
	public DataInputParameter getCipherText()
	{
		return cipherText;
	}

	/**
	 * Set the passphrase to unlock the private key.
	 *
	 * @param passphrase The passphrase.
	 */
	public void setPassphrase(DataInputParameter passphrase)
	{
		this.passphrase = passphrase;
	}

	/**
	 * Get the passphrase to unlock the private key.
	 *
	 * @return The passphrase.
	 */
	public DataInputParameter getPassphrase()
	{
		return passphrase;
	}

	/**
	 * Set the decrypted clear text.
	 *
	 * @param clearText The clear text.
	 */
	public void setClearText(DataOutputParameter clearText)
	{
		this.clearText = clearText;
	}

	/**
	 * Get the decrypted clear text.
	 *
	 * @return The clear text.
	 */
	public DataOutputParameter getClearText()
	{
		return clearText;
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

	private static void decrypt(InputStream in, InputStream key, char[] passwd, OutputStream out) throws PGPException, IOException, NoSuchProviderException
	{
		in = getDecoderStream(in);
		JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
		PGPEncryptedDataList enc;
		Object o = pgpF.nextObject();
		//
		// the first object might be a PGP marker packet.
		//
		if (o instanceof PGPEncryptedDataList)
		{
			enc = (PGPEncryptedDataList)o;
		}
		else
		{
			enc = (PGPEncryptedDataList)pgpF.nextObject();
		}
		//
		// find the secret key
		//
		Iterator it = enc.getEncryptedDataObjects();
		PGPPrivateKey sKey = null;
		PGPPublicKeyEncryptedData pbe = null;
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(getDecoderStream(key), new JcaKeyFingerprintCalculator());
		while (sKey == null && it.hasNext())
		{
			pbe = (PGPPublicKeyEncryptedData)it.next();
			sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
		}
		if (sKey == null)
		{
			throw new IllegalArgumentException("Secret key for message not found");
		}
		InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
		JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
		PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();
		InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
		JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedStream);
		Object message = pgpFact.nextObject();
		if (message instanceof PGPLiteralData)
		{
			PGPLiteralData ld = (PGPLiteralData)message;
			InputStream unc = ld.getInputStream();
			OutputStream fOut = new BufferedOutputStream(out);
			Streams.pipeAll(unc, fOut);
			fOut.close();
		}
		else if (message instanceof PGPOnePassSignatureList)
		{
			throw new PGPException("Encrypted message contains a signed message - not literal data");
		}
		else
		{
			throw new PGPException("Message is not a simple encrypted file - type unknown");
		}
		if (pbe.isIntegrityProtected())
		{
			if (!pbe.verify())
			{
				log.warn("Message failed integrity check");
			}
			else
			{
				log.debug("Message integrity check passed");
			}
		}
		else
		{
			log.debug("No message integrity check");
		}
	}

	/**
	 * Search a secret key ring collection for a secret key corresponding to keyID if it
	 * exists.
	 *
	 * @param pgpSec a secret key ring collection.
	 * @param keyID keyID we want.
	 * @param pass passphrase to decrypt secret key with.
	 * @return the private key.
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException, NoSuchProviderException
	{
		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
		if (pgpSecKey == null)
		{
			return null;
		}
		return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
	}

	private static final int READ_AHEAD = 60;

	/**
	 * Obtains a stream that can be used to read PGP data from the provided stream.
	 * <p>
	 * If the initial bytes of the underlying stream are binary PGP encodings, then the stream will
	 * be returned directly, otherwise an {@link ArmoredInputStream} is used to wrap the provided
	 * stream and remove ASCII-Armored encoding.
	 * </p>
	 *
	 * @param in the stream to be checked and possibly wrapped.
	 * @return a stream that will return PGP binary encoded data.
	 * @throws IOException if an error occurs reading the stream, or initialising the
	 *                     {@link ArmoredInputStream}.
	 */
	private static InputStream getDecoderStream(InputStream in) throws IOException
	{
		if (!in.markSupported())
		{
			in = new BufferedInputStreamExt(in);
		}
		in.mark(READ_AHEAD);
		int ch = in.read();
		if ((ch & 0x80) != 0)
		{
			in.reset();
			return in;
		}
		else
		{
			if (!isPossiblyBase64(ch))
			{
				in.reset();
				return new ArmoredInputStream(in);
			}
			byte[] buf = new byte[READ_AHEAD];
			int count = 1;
			int index = 1;
			buf[0] = (byte) ch;
			while (count != READ_AHEAD && (ch = in.read()) >= 0)
			{
				if (!isPossiblyBase64(ch))
				{
					in.reset();
					return new ArmoredInputStream(in);
				}
				if (ch != '\n' && ch != '\r')
				{
					buf[index++] = (byte) ch;
				}
				count++;
			}
			in.reset();
			//
			// nothing but new lines, little else, assume regular armoring
			//
			if (count < 4)
			{
				return new ArmoredInputStream(in);
			}
			//
			// test our non-blank data
			//
			byte[] firstBlock = new byte[8];
			System.arraycopy(buf, 0, firstBlock, 0, firstBlock.length);
			try
			{
				byte[] decoded = Base64.decode(firstBlock);
				//
				// it's a base64 PGP block.
				//
				if ((decoded[0] & 0x80) != 0)
				{
					return new ArmoredInputStream(in, false);
				}
				return new ArmoredInputStream(in);
			}
			catch (DecoderException e)
			{
				throw new IOException(e.getMessage());
			}
		}
	}

	private static boolean isPossiblyBase64(int ch)
	{
		return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
				|| (ch >= '0' && ch <= '9') || (ch == '+') || (ch == '/')
				|| (ch == '\r') || (ch == '\n');
	}

	private static class BufferedInputStreamExt extends BufferedInputStream
	{
		BufferedInputStreamExt(InputStream input)
		{
			super (input);
		}
		public synchronized int available() throws IOException
		{
			int result = super.available();
			if (result < 0)
			{
				result = Integer.MAX_VALUE;
			}
			return result;
		}
	}
}
