package com.adaptris.security.pgp;

import com.adaptris.annotation.AdapterComponent;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.ServiceException;
import com.adaptris.core.common.MetadataStreamInputParameter;
import com.adaptris.core.common.PayloadStreamInputParameter;
import com.adaptris.core.common.PayloadStreamOutputParameter;
import com.adaptris.interlok.config.DataInputParameter;
import com.adaptris.interlok.config.DataOutputParameter;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * This service provides a way to verify GPG/PGP signed messages. It
 * requires the public key of whom signed the message, the signed
 * message, and (if the signature is detached) the signature. It will
 * will also optionally return the original/unsigned message
 * (especially useful if the signature was not detached).
 *
 * <pre>{@code
 *    <pgp-verify>
 *        <unique-id>jovial-elion</unique-id>
 *        <public-key class="constant-data-input-parameter">
 *            <value>-----BEGIN PGP PUBLIC KEY BLOCK-----
 *
 *    mQENBF2ckxABCAC5Kfu39ky3OIXkxwWOJx70G2dLRYvDMHXf3ZraUPNRMIhh3ZGx
 *    -----END PGP PUBLIC KEY BLOCK-----</value>
 *        </public-key>
 *        <signed-message class="stream-payload-input-parameter"/>         <!-- signed message (without signature, as it's detached) -->
 *        <signature class="metadata-stream-input-parameter">              <!-- detached signature comes into message metadata -->
 *            <metadata-key>signature</metadata-key>
 *        </signature>
 *        <original-message class="string-payload-data-output-parameter"/> <!-- optional original message, without signature -->
 *    </pgp-verify>
 * }</pre>
 *
 * @author aanderson
 * @config pgp-verify
 */
@XStreamAlias("pgp-verify")
@AdapterComponent
@ComponentProfile(summary = "Verify sign data using a PGP/GPG public key", tag = "pgp,gpg,sign,signature,verify,public key", since="3.9.2")
@DisplayOrder(order = { "publicKey", "signedMessage", "signature", "originalMessage" })
public class PGPVerifyService extends PGPService
{
	private static transient Logger log = LoggerFactory.getLogger(PGPVerifyService.class);

	@NotNull
	@Valid
	private DataInputParameter publicKey = new MetadataStreamInputParameter();

	@NotNull
	@Valid
	private DataInputParameter signedMessage = new PayloadStreamInputParameter();

	@Valid
	private DataInputParameter signature = new MetadataStreamInputParameter();

	@Valid
	private DataOutputParameter originalMessage = new PayloadStreamOutputParameter();

	/**
	 * {@inheritDoc}.
	 */
	@Override
	public void doService(AdaptrisMessage message) throws ServiceException
	{
		try
		{
			InputStream key = extractStream(message, publicKey, "Could not read public key");
			InputStream data = extractStream(message, signedMessage, "Could not read cipher text message to verify");
			InputStream sig = null; // if the signature continues to be null then it can't be a detached signature
			if (signature != null)
			{
				sig = extractStream(message, signature, "Could not read signature to verify");
			}
			ByteArrayOutputStream original = new ByteArrayOutputStream();
			if (sig != null)
			{
				verify(data, sig, key, original);
			}
			else
			{
				verify(data, key, original);
			}
			insertStream(message, originalMessage, original);
		}
		catch (Exception e)
		{
			log.error("An error occurred during PGP verification", e);
			throw new ServiceException(e);
		}
	}

	/**
	 * Set the private key for decryption.
	 *
	 * @param publicKey The private key.
	 */
	public void setPublicKey(DataInputParameter publicKey)
	{
		this.publicKey = publicKey;
	}

	/**
	 * Get the private key for decryption.
	 *
	 * @return The private key.
	 */
	public DataInputParameter getPublicKey()
	{
		return publicKey;
	}

	/**
	 * Set the signed message to verify.
	 *
	 * @param signedMessage The signed message.
	 */
	public void setSignedMessage(DataInputParameter signedMessage)
	{
		this.signedMessage = signedMessage;
	}

	/**
	 * Get the signed message to verify.
	 *
	 * @return The signed message.
	 */
	public DataInputParameter getSignedMessage()
	{
		return signedMessage;
	}

	/**
	 * Set the signature to verify.
	 *
	 * @param signature The signature.
	 */
	public void setSignature(DataInputParameter signature)
	{
		this.signature = signature;
	}

	/**
	 * Get the signature to verify.
	 *
	 * @return The signature.
	 */
	public DataInputParameter getSignature()
	{
		return signature;
	}

	/**
	 * Set the unsigned message.
	 *
	 * @param message The message.
	 */
	public void setOriginalMessage(DataOutputParameter message)
	{
		this.originalMessage = message;
	}

	/**
	 * Get the unsigned message.
	 *
	 * @return The message.
	 */
	public DataOutputParameter getOriginalMessage()
	{
		return originalMessage;
	}

	/**
	 * Verify a clear inline signature.
	 *
	 * @param in  The signed message.
	 * @param key The public key.
	 * @param out The original, unsigned message.
	 * @throws Exception Thrown if there's a problem verifying the signature.
	 */
	private static void verify(InputStream in, InputStream key, ByteArrayOutputStream out) throws Exception
	{
		ArmoredInputStream aIn = new ArmoredInputStream(in);
		//
		// write out signed section using the local line separator.
		// note: trailing white space needs to be removed from the end of
		// each line RFC 4880 Section 7.1
		//
		ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
		int lookAhead = readInputLine(lineOut, aIn);
		byte[] lineSep = getLineSeparator();
		if (lookAhead != -1 && aIn.isClearText())
		{
			byte[] line = lineOut.toByteArray();
			out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
			out.write(lineSep);
			while (lookAhead != -1 && aIn.isClearText())
			{
				lookAhead = readInputLine(lineOut, lookAhead, aIn);
				line = lineOut.toByteArray();
				out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
				out.write(lineSep);
			}
		}
		else
		{
			// a single line file
			if (lookAhead != -1)
			{
				byte[] line = lineOut.toByteArray();
				out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
				out.write(lineSep);
			}
		}
		out.close();
		PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(getDecoderStream(key), new JcaKeyFingerprintCalculator());
		JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(aIn);
		PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();
		PGPSignature sig = p3.get(0);
		PGPPublicKey publicKey = pgpRings.getPublicKey(sig.getKeyID());
		sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider(PROVIDER), publicKey);
		//
		// read the input, making sure we ignore the last newline.
		//
		InputStream sigIn = new ByteArrayInputStream(out.toByteArray());
		lookAhead = readInputLine(lineOut, sigIn);
		processLine(sig, lineOut.toByteArray());
		if (lookAhead != -1)
		{
			do
			{
				lookAhead = readInputLine(lineOut, lookAhead, sigIn);
				sig.update((byte)'\r');
				sig.update((byte)'\n');
				processLine(sig, lineOut.toByteArray());
			}
			while (lookAhead != -1);
		}
		sigIn.close();
		if (!sig.verify())
		{
			throw new PGPException("Signature verification failed");
		}
	}

	/**
	 * Verify a detached signature for a given message.
	 *
	 * @param inMessage   The original message.
	 * @param inSignature The detached signature.
	 * @param key         The public key.
	 * @param out         The original message.
	 * @throws Exception Thrown if there's a problem verifying the signature.
	 */
	private static void verify(InputStream inMessage, InputStream inSignature, InputStream key, ByteArrayOutputStream out) throws Exception
	{
		inSignature = getDecoderStream(inSignature);
		JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(inSignature);
		PGPSignatureList p3;
		Object o = pgpFact.nextObject();
		if (o instanceof PGPCompressedData)
		{
			PGPCompressedData c1 = (PGPCompressedData)o;
			pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
			p3 = (PGPSignatureList)pgpFact.nextObject();
		}
		else
		{
			p3 = (PGPSignatureList)o;
		}
		PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(getDecoderStream(key), new JcaKeyFingerprintCalculator());
		PGPSignature sig = p3.get(0);
		PGPPublicKey pubKey = pgpPubRingCollection.getPublicKey(sig.getKeyID());
		sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider(PROVIDER), pubKey);
		int ch;
		while ((ch = inMessage.read()) >= 0)
		{
			sig.update((byte)ch);
			out.write((byte)ch);
		}
		inMessage.close();
		if (!sig.verify())
		{
			throw new PGPException("Signature verification failed");
		}
	}
}
