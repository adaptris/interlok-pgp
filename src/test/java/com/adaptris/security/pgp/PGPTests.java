package com.adaptris.security.pgp;

import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.MultiPayloadAdaptrisMessage;
import com.adaptris.core.MultiPayloadMessageFactory;
import com.adaptris.core.ServiceCase;
import com.adaptris.core.common.MultiPayloadStreamInputParameter;
import com.adaptris.core.common.MultiPayloadStreamOutputParameter;
import com.adaptris.core.common.MultiPayloadStringInputParameter;
import com.adaptris.core.common.MultiPayloadStringOutputParameter;
import com.adaptris.interlok.config.DataInputParameter;
import com.adaptris.interlok.config.DataOutputParameter;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.junit.Before;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

abstract class PGPTests extends ServiceCase
{
	protected static final String MESSAGE = "Spicy jalapeno bacon ipsum dolor amet shankle hamburger tri-tip, filet mignon ham sirloin prosciutto pig andouille pork belly pork loin. Tail beef kielbasa alcatra salami doner turkey corned beef fatback leberkas pastrami shoulder spare ribs filet mignon pork loin. Cupim doner pastrami chicken venison pork loin. Ribeye pork tri-tip cow buffalo rump boudin sirloin short ribs picanha salami." + System.getProperty("line.separator");
	protected static final String PASSPHRASE = "passphrase";

	private static final String ID = "email@example.com";

	protected PGPSecretKey privateKey;
	protected PGPPublicKey publicKey;

	protected String PAYLOAD_KEY = "key";
	protected String PAYLOAD_CIPHERTEXT = "ciphertext";
	protected String PAYLOAD_PLAINTEXT = "plaintext";

	@Before
	public void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", PGPService.PROVIDER);
		kpg.initialize(1024);
		KeyPair kp = kpg.generateKeyPair();
		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
		PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kp, new Date());
		privateKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, ID, sha1Calc, null, null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider(PGPService.PROVIDER).build(PASSPHRASE.toCharArray()));
		publicKey = privateKey.getPublicKey();
		/*
		try (InputStream i = new FileInputStream("C:\\adaptris\\testkey.asc"))
		{
			PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(i), new JcaKeyFingerprintCalculator());
			Iterator keyRingIter = pgpSec.getKeyRings();
			while (keyRingIter.hasNext() && privateKey == null)
			{
				PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
				Iterator keyIter = keyRing.getSecretKeys();
				while (keyIter.hasNext() && privateKey == null)
				{
					PGPSecretKey key = (PGPSecretKey)keyIter.next();
					if (key.isSigningKey())
					{
						privateKey = key;
					}
				}
			}
		}
		try (InputStream i = new FileInputStream("C:\\adaptris\\testkey.asc.pub"))
		{
			PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(i), new JcaKeyFingerprintCalculator());
			Iterator keyRingIter = pgpPub.getKeyRings();
			while (keyRingIter.hasNext() && publicKey == null)
			{
				PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();
				Iterator keyIter = keyRing.getPublicKeys();
				while (keyIter.hasNext() && publicKey == null)
				{
					PGPPublicKey key = (PGPPublicKey)keyIter.next();
					if (key.isEncryptionKey())
					{
						publicKey = key;
					}
				}
			}
		}
		*/
	}

	/**
	 * Create a new message with a known default payload.
	 *
	 * @return A new message
	 *
	 * @throws Exception Something went wrong!
	 */
	protected MultiPayloadAdaptrisMessage newMessage() throws Exception
	{
		return newMessage(false);
	}

	/**
	 * Create a new message, with either a default payload or the private key passphrase.
	 *
	 * @param passphrase If true, the payload will be the private key passphrase.
	 *
	 * @return A new message.
	 *
	 * @throws Exception Something went wrong!
	 */
	protected MultiPayloadAdaptrisMessage newMessage(boolean passphrase) throws Exception
	{
		MultiPayloadMessageFactory factory = new MultiPayloadMessageFactory();
		return (MultiPayloadAdaptrisMessage)factory.newMessage(PAYLOAD_PLAINTEXT, passphrase ? PASSPHRASE : MESSAGE, factory.getDefaultCharEncoding());
	}

	/**
	 * Create a new message, with the payload of the original.
	 *
	 * @param original The message to clone.
	 *
	 * @return A new message.
	 *
	 * @throws Exception Something went wrong!
	 */
	protected MultiPayloadAdaptrisMessage newMessage(MultiPayloadAdaptrisMessage original) throws Exception
	{
		MultiPayloadAdaptrisMessage message = (MultiPayloadAdaptrisMessage)new MultiPayloadMessageFactory().newMessage(PAYLOAD_CIPHERTEXT, original.getPayload(PAYLOAD_CIPHERTEXT));
		message.setContentEncoding(original.getContentEncoding());
		return message;
	}

	/**
	 * Get the private key.
	 *
	 * @param key The private key object.
	 * @param armor Whether to ASCII armor the key.
	 *
	 * @return The key.
	 *
	 * @throws Exception Something went wrong!
	 */
	protected byte[] getKey(PGPSecretKey key, boolean armor) throws Exception
	{
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		if (armor)
		{
			ArmoredOutputStream armored = new ArmoredOutputStream(keyBytes);
			key.encode(armored);
			armored.close();
		}
		else
		{
			key.encode(keyBytes);
		}
		return keyBytes.toByteArray();
	}

	/**
	 * Get the public key.
	 *
	 * @param key The public key object.
	 * @param armor Whether to ASCII armor the key.
	 *
	 * @return The key.
	 *
	 * @throws Exception Something went wrong!
	 */
	protected byte[] getKey(PGPPublicKey key, boolean armor) throws Exception
	{
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		if (armor)
		{
			ArmoredOutputStream armored = new ArmoredOutputStream(keyBytes);
			key.encode(armored);
			armored.close();
		}
		else
		{
			key.encode(keyBytes);
		}
		return keyBytes.toByteArray();
	}

	/**
	 * Get an input parameter for the key.
	 *
	 * @param armor Whether the key will be ASCII armor encoded.
	 *
	 * @return A data input parameter for the key.
	 */
	protected DataInputParameter getKeyInput(boolean armor)
	{
		DataInputParameter keyParam;
		if (armor)
		{
			keyParam = new MultiPayloadStringInputParameter();
			((MultiPayloadStringInputParameter)keyParam).setPayloadId(PAYLOAD_KEY);
		}
		else
		{
			keyParam = new MultiPayloadStreamInputParameter();
			((MultiPayloadStreamInputParameter)keyParam).setPayloadId(PAYLOAD_KEY);
		}
		return keyParam;
	}

	/**
	 * Get an input parameter for the cipher text.
	 *
	 * @param armor Whether the cipher text will be ASCII armor encoded.
	 *
	 * @return A data input parameter for the cipher text.
	 */
	protected DataInputParameter getCipherInput(boolean armor)
	{
		DataInputParameter cipherParam;
		if (armor)
		{
			cipherParam = new MultiPayloadStringInputParameter();
			((MultiPayloadStringInputParameter)cipherParam).setPayloadId(PAYLOAD_CIPHERTEXT);
		}
		else
		{
			cipherParam = new MultiPayloadStreamInputParameter();
			((MultiPayloadStreamInputParameter)cipherParam).setPayloadId(PAYLOAD_CIPHERTEXT);
		}
		return cipherParam;
	}

	/**
	 * Get an output parameter for the cipher text.
	 *
	 * @param armor Whether the cipher text will be ASCII armor encoded.
	 *
	 * @return A data output parameter for the cipher text.
	 */
	protected DataOutputParameter getCipherOutput(boolean armor)
	{
		DataOutputParameter cipherParam;
		if (armor)
		{
			cipherParam = new MultiPayloadStringOutputParameter();
			((MultiPayloadStringOutputParameter)cipherParam).setPayloadId(PAYLOAD_CIPHERTEXT);
		}
		else
		{
			cipherParam = new MultiPayloadStreamOutputParameter();
			((MultiPayloadStreamOutputParameter)cipherParam).setPayloadId(PAYLOAD_CIPHERTEXT);
		}
		return cipherParam;
	}
}
