package com.adaptris.security.pgp;

import com.adaptris.annotation.AdapterComponent;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
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
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.InvalidParameterException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

@XStreamAlias("pgp-signature")
@AdapterComponent
@ComponentProfile(summary = "Sign data using a PGP/GPG private key", tag = "pgp,gpg,sign,signature,private key")
public class PGPSignService extends ServiceImp
{
	private static transient Logger log = LoggerFactory.getLogger(PGPSignService.class);

	private static final Charset CHARSET = Charset.forName("UTF-8");

	private static final int DIGEST = HashAlgorithmTags.SHA1;

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
	private DataInputParameter dataToSign = new PayloadStreamInputParameter();

	@NotNull
	@Valid
	private DataOutputParameter signature = new PayloadStreamOutputParameter();

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
			Object data = this.dataToSign.extract(message);
			if (data instanceof String)
			{
				data = new ByteArrayInputStream(((String)data).getBytes(CHARSET));
			}
			if (!(data instanceof InputStream))
			{
				throw new InterlokException("Could not read data");
			}

			ByteArrayOutputStream clearText = new ByteArrayOutputStream();

			sign((InputStream)data, (InputStream)key, ((String)passphrase).toCharArray(), DIGEST, clearText);

			try
			{
				this.signature.insert(clearText.toString(CHARSET.toString()), message);
			}
			catch (InvalidParameterException e)
			{
				/* this.clearText was not expecting a String, must be an InputStreamWithEncoding */
				this.signature.insert(new InputStreamWithEncoding(new ByteArrayInputStream(clearText.toByteArray()), null), message);
			}
		}
		catch (Exception e)
		{
			log.error("An error occurred during PGP signing", e);
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
	 * Set the data to sign.
	 *
	 * @param dataToSign The data to sign.
	 */
	public void setDataToSign(DataInputParameter dataToSign)
	{
		this.dataToSign = dataToSign;
	}

	/**
	 * Get the data to sign.
	 *
	 * @return The data to sign.
	 */
	public DataInputParameter getDataToSign()
	{
		return dataToSign;
	}

	/**
	 * Set the signature.
	 *
	 * @param signature The signature.
	 */
	public void setSignature(DataOutputParameter signature)
	{
		this.signature = signature;
	}

	/**
	 * Get the signature.
	 *
	 * @return The signature.
	 */
	public DataOutputParameter getSignature()
	{
		return signature;
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
	public void prepare() throws CoreException
	{
		/* unused */
	}

	private static void sign(InputStream in, InputStream key, char[] passwd, int digest, OutputStream out) throws PGPException, IOException, SignatureException
	{
		PGPSecretKey pgpSecKey = readSecretKey(key);
		PGPPrivateKey pgpPrivKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passwd));
		PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), digest).setProvider("BC"));
		PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

		sGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivKey);

		Iterator it = pgpSecKey.getPublicKey().getUserIDs();
		if (it.hasNext())
		{
			spGen.setSignerUserID(false, (String)it.next());
			sGen.setHashedSubpackets(spGen.generate());
		}
		InputStream fIn = new BufferedInputStream(in);
		ArmoredOutputStream aOut = new ArmoredOutputStream(out);
		aOut.beginClearText(digest);
		//
		// note the last \n/\r/\r\n in the file is ignored
		//
		ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
		int lookAhead = readInputLine(lineOut, fIn);
		processLine(aOut, sGen, lineOut.toByteArray());
		if (lookAhead != -1)
		{
			do
			{
				lookAhead = readInputLine(lineOut, lookAhead, fIn);
				sGen.update((byte)'\r');
				sGen.update((byte)'\n');
				processLine(aOut, sGen, lineOut.toByteArray());
			}
			while (lookAhead != -1);
		}
		fIn.close();
		aOut.endClearText();
		BCPGOutputStream bOut = new BCPGOutputStream(aOut);
		sGen.generate().encode(bOut);
		aOut.close();
	}

	/**
	 * A simple routine that opens a key ring file and loads the first available key
	 * suitable for signature generation.
	 *
	 * @param input stream to read the secret key ring collection from.
	 * @return a secret key.
	 * @throws IOException on a problem with using the input stream.
	 * @throws PGPException if there is an issue parsing the input stream.
	 */
	private static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException
	{
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(Utils.getDecoderStream(input), new JcaKeyFingerprintCalculator());
		//
		// we just loop through the collection till we find a key suitable for encryption, in the real
		// world you would probably want to be a bit smarter about this.
		//
		Iterator keyRingIter = pgpSec.getKeyRings();
		while (keyRingIter.hasNext())
		{
			PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
			Iterator keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext())
			{
				PGPSecretKey key = (PGPSecretKey)keyIter.next();
				if (key.isSigningKey())
				{
					return key;
				}
			}
		}
		throw new IllegalArgumentException("Can't find signing key in key ring");
	}

	private static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn) throws IOException
	{
		bOut.reset();
		int lookAhead = -1;
		int ch;
		while ((ch = fIn.read()) >= 0)
		{
			bOut.write(ch);
			if (ch == '\r' || ch == '\n')
			{
				lookAhead = readPassedEOL(bOut, ch, fIn);
				break;
			}
		}
		return lookAhead;
	}

	private static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn) throws IOException
	{
		bOut.reset();
		int ch = lookAhead;
		do
		{
			bOut.write(ch);
			if (ch == '\r' || ch == '\n')
			{
				lookAhead = readPassedEOL(bOut, ch, fIn);
				break;
			}
		}
		while ((ch = fIn.read()) >= 0);
		if (ch < 0)
		{
			lookAhead = -1;
		}
		return lookAhead;
	}

	private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn) throws IOException
	{
		int lookAhead = fIn.read();
		if (lastCh == '\r' && lookAhead == '\n')
		{
			bOut.write(lookAhead);
			lookAhead = fIn.read();
		}
		return lookAhead;
	}

	private static void processLine(OutputStream aOut, PGPSignatureGenerator sGen, byte[] line) throws SignatureException, IOException
	{
		// note: trailing white space needs to be removed from the end of
		// each line for signature calculation RFC 4880 Section 7.1
		int length = getLengthWithoutWhiteSpace(line);
		if (length > 0)
		{
			sGen.update(line, 0, length);
		}
		aOut.write(line, 0, line.length);
	}

	private static int getLengthWithoutWhiteSpace(byte[] line)
	{
		int    end = line.length - 1;
		while (end >= 0 && isWhiteSpace(line[end]))
		{
			end--;
		}
		return end + 1;
	}

	private static boolean isWhiteSpace(byte b)
	{
		return isLineEnding(b) || b == '\t' || b == ' ';
	}

	private static boolean isLineEnding(byte b)
	{
		return b == '\r' || b == '\n';
	}
}
