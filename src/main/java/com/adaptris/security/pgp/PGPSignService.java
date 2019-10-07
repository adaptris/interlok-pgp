package com.adaptris.security.pgp;

import com.adaptris.annotation.AdapterComponent;
import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.InputFieldDefault;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.ServiceException;
import com.adaptris.core.ServiceImp;
import com.adaptris.core.common.InputStreamWithEncoding;
import com.adaptris.core.common.MetadataDataOutputParameter;
import com.adaptris.core.common.MetadataStreamInputParameter;
import com.adaptris.core.common.PayloadStreamInputParameter;
import com.adaptris.core.common.PayloadStreamOutputParameter;
import com.adaptris.interlok.InterlokException;
import com.adaptris.interlok.config.DataInputParameter;
import com.adaptris.interlok.config.DataOutputParameter;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.BooleanUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
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

	/* TODO digest could be an advanced option */
	private static final int DIGEST = HashAlgorithmTags.SHA256;

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

	@Valid
	@AdvancedConfig
	@InputFieldDefault(value = "true")
	private Boolean armorEncoding = true;

	@Valid
	@AdvancedConfig
	@InputFieldDefault(value = "true")
	private Boolean detachedSignature = true;

	@NotNull
	@Valid
	private DataOutputParameter signature = new MetadataDataOutputParameter();

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
				throw new InterlokException("Could not read private key");
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
				throw new InterlokException("Could not read private key");
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

			if (detachedSignature)
			{
				signDetached((InputStream)data, (InputStream)key, ((String)passphrase).toCharArray(), DIGEST, armorEncoding, clearText);
			}
			else
			{
				signClear((InputStream)data, (InputStream)key, ((String)passphrase).toCharArray(), DIGEST, clearText);
			}

			try
			{
				this.signature.insert(clearText.toString(CHARSET.toString()), message);
			}
			catch (ClassCastException e)
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
	 * Set whether the signature output should be ASCII armor encoded.
	 *
	 * @param armorEncoding Whether the signature should be armor encoded.
	 */
	public void setArmorEncoding(Boolean armorEncoding)
	{
		this.armorEncoding = BooleanUtils.toBooleanDefaultIfNull(armorEncoding, true);
	}

	/**
	 * Get whether the signature output should be ASCII armor encoded.
	 *
	 * @return Whether the signature should be armor encoded.
	 */
	public Boolean getArmorEncoding()
	{
		return armorEncoding;
	}

	/**
	 * Set whether the signature should be detached from the message.
	 *
	 * @param detachedSignature Whether the signature should be detached.
	 */
	public void setDetachedSignature(Boolean detachedSignature)
	{
		this.detachedSignature = BooleanUtils.toBooleanDefaultIfNull(detachedSignature, true);
	}

	/**
	 * Get whether the signature should be detached from the message.
	 *
	 * @return Whether the signature should be detached.
	 */
	public Boolean getDetachedSignature()
	{
		return detachedSignature;
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

	private static void signClear(InputStream in, InputStream key, char[] passwd, int digest, OutputStream out) throws PGPException, IOException, SignatureException
	{
		PGPSecretKey pgpSec = readSecretKey(key);
		PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passwd));
		PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), digest).setProvider("BC"));
		PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
		sGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivKey);
		Iterator it = pgpSec.getPublicKey().getUserIDs();
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
		int lookAhead = Utils.readInputLine(lineOut, fIn);
		Utils.processLine(aOut, sGen, lineOut.toByteArray());
		if (lookAhead != -1)
		{
			do
			{
				lookAhead = Utils.readInputLine(lineOut, lookAhead, fIn);
				sGen.update((byte)'\r');
				sGen.update((byte)'\n');
				Utils.processLine(aOut, sGen, lineOut.toByteArray());
			}
			while (lookAhead != -1);
		}
		fIn.close();
		aOut.endClearText();
		BCPGOutputStream bOut = new BCPGOutputStream(aOut);
		sGen.generate().encode(bOut);
		aOut.close();
	}

	private static void signDetached(InputStream in, InputStream key, char[] passwd, int digest, boolean armor, OutputStream out) throws PGPException, IOException, SignatureException
	{
		if (armor)
		{
			out = new ArmoredOutputStream(out);
		}
		PGPSecretKey pgpSec = readSecretKey(key);
		PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passwd));
		PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), digest).setProvider("BC"));
		sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
		BCPGOutputStream bOut = new BCPGOutputStream(out);
		int ch;
		while ((ch = in.read()) >= 0)
		{
			sGen.update((byte)ch);
		}
		sGen.generate().encode(bOut);
		if (armor)
		{
			out.close();
		}
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
}
