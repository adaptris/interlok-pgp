package com.adaptris.security.pgp;

import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.ServiceCase;
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
	protected static final String ID = "email@example.com";
	protected static final String PASSPHRASE = "passphrase";

	protected PGPSecretKey privateKey;
	protected PGPPublicKey publicKey;

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
	protected AdaptrisMessage newMessage() throws Exception
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
	protected AdaptrisMessage newMessage(boolean passphrase) throws Exception
	{
		return AdaptrisMessageFactory.getDefaultInstance().newMessage(passphrase ? PASSPHRASE : MESSAGE);
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
	protected AdaptrisMessage newMessage(AdaptrisMessage original) throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(original.getPayload());
		message.setContentEncoding(original.getContentEncoding());
		return message;
	}

	/**
	 * Get the ASCII armored private key.
	 *
	 * @param key The raw private key data.
	 *
	 * @return The ASCII armored key.
	 *
	 * @throws Exception Something went wrong!
	 */
	protected String getKey(PGPSecretKey key) throws Exception
	{
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		ArmoredOutputStream armored = new ArmoredOutputStream(keyBytes);
		key.encode(armored);
		armored.close();
		return keyBytes.toString();
	}

	/**
	 * Get the ASCII armored public key.
	 *
	 * @param key The raw public key data.
	 *
	 * @return The ASCII armored key.
	 *
	 * @throws Exception Something went wrong!
	 */
	protected String getKey(PGPPublicKey key) throws Exception
	{
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		ArmoredOutputStream armored = new ArmoredOutputStream(keyBytes);
		key.encode(armored);
		armored.close();
		return keyBytes.toString();
	}
}
