package com.adaptris.security.pgp;

import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.ServiceCase;
import com.adaptris.core.common.ConstantDataInputParameter;
import com.adaptris.core.common.PayloadStreamInputParameter;
import com.adaptris.core.common.PayloadStreamOutputParameter;
import com.adaptris.core.common.StringPayloadDataInputParameter;
import com.adaptris.core.common.StringPayloadDataOutputParameter;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

public class PGPEncryptTest extends ServiceCase
{
	private static final String MESSAGE = "Spicy jalapeno bacon ipsum dolor amet shankle hamburger tri-tip, filet mignon ham sirloin prosciutto pig andouille pork belly pork loin. Tail beef kielbasa alcatra salami doner turkey corned beef fatback leberkas pastrami shoulder spare ribs filet mignon pork loin. Cupim doner pastrami chicken venison pork loin. Ribeye pork tri-tip cow buffalo rump boudin sirloin short ribs picanha salami.";
	private static final String ID = "email@example.com";
	private static final String PASSPHRASE = "passphrase";

	private PGPPublicKeyRing publicKey;
	private PGPSecretKeyRing privateKey;

	@Before
	public void setUp() throws Exception
	{
		PGPKeyRingGenerator keyRingGenerator = generateKeyRingGenerator(ID, PASSPHRASE, 0xc0);
		publicKey = keyRingGenerator.generatePublicKeyRing();
		privateKey = keyRingGenerator.generateSecretKeyRing();
	}

	@Test
	public void testEntireWorkflow() throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
		PGPEncryptService encrypt = getEncryptService(publicKey, true, true);

		encrypt.doService(message);

		message = AdaptrisMessageFactory.getDefaultInstance().newMessage(message.getPayload());
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE);

		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testWorkflowNonArmored() throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
		PGPEncryptService encrypt = getEncryptService(publicKey, false, true);

		encrypt.doService(message);

		message = AdaptrisMessageFactory.getDefaultInstance().newMessage(message.getPayload());
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE);

		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testWorkflowNoIntegrity() throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
		PGPEncryptService encrypt = getEncryptService(publicKey, true, false);

		encrypt.doService(message);

		message = AdaptrisMessageFactory.getDefaultInstance().newMessage(message.getPayload());
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE);

		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testWorkflowNoArmorOrIntegrity() throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
		PGPEncryptService encrypt = getEncryptService(publicKey, false, false);

		encrypt.doService(message);

		message = AdaptrisMessageFactory.getDefaultInstance().newMessage(message.getPayload());
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE);

		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	private PGPEncryptService getEncryptService(PGPPublicKeyRing key, boolean armor, boolean integrity) throws Exception
	{
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		ArmoredOutputStream armoredKey = new ArmoredOutputStream(keyBytes);
		key.encode(armoredKey);
		armoredKey.close();

		PGPEncryptService service = new PGPEncryptService();
		service.setKey(new ConstantDataInputParameter(keyBytes.toString()));
		service.setClearText(new StringPayloadDataInputParameter());
		service.setCipherText(armor ? new StringPayloadDataOutputParameter() : new PayloadStreamOutputParameter());
		service.setArmorEncoding(armor);
		service.setIntegrityCheck(integrity);
		return service;
	}

	private PGPDecryptService getDecryptService(PGPSecretKeyRing key, String passphrase) throws Exception
	{
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		ArmoredOutputStream armoredKey = new ArmoredOutputStream(keyBytes);
		key.encode(armoredKey);
		armoredKey.close();

		PGPDecryptService service = new PGPDecryptService();
		service.setKey(new ConstantDataInputParameter(keyBytes.toString()));
		service.setPassphrase(new ConstantDataInputParameter(passphrase));
		service.setCipherText(new PayloadStreamInputParameter());
		service.setClearText(new StringPayloadDataOutputParameter());
		return service;
	}

	// Note: s2kcount is a number between 0 and 0xff that controls the number of times to iterate the password hash before use. More
	// iterations are useful against offline attacks, as it takes more time to check each password. The actual number of iterations is
	// rather complex, and also depends on the hash function in use. Refer to Section 3.7.1.3 in rfc4880.txt. Bigger numbers give
	// you more iterations.  As a rough rule of thumb, when using SHA256 as the hashing function, 0x10 gives you about 64
	// iterations, 0x20 about 128, 0x30 about 256 and so on till 0xf0, or about 1 million iterations. The maximum you can go to is
	// 0xff, or about 2 million iterations.  I'll use 0xc0 as a default -- about 130,000 iterations.
	private static PGPKeyRingGenerator generateKeyRingGenerator(String id, String pass, int s2kcount) throws Exception
	{
		// This object generates individual key-pairs.
		RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();

		// Boilerplate RSA parameters, no need to change anything
		// except for the RSA key-size (2048). You can use whatever key-size makes sense for you -- 4096, etc.
		kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 2048, 12));

		// First create the master (signing) key with the generator.
		PGPKeyPair rsakp_sign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
		// Then an encryption subkey.
		PGPKeyPair rsakp_enc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

		// Add a self-signature on the id
		PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();

		// Add signed metadata on the signature.
		// 1) Declare its purpose
		signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
		// 2) Set preferences for secondary crypto algorithms to use when sending messages to this key.
		signhashgen.setPreferredSymmetricAlgorithms
				(false, new int[]{
						SymmetricKeyAlgorithmTags.AES_256,
						SymmetricKeyAlgorithmTags.AES_192,
						SymmetricKeyAlgorithmTags.AES_128
				});
		signhashgen.setPreferredHashAlgorithms
				(false, new int[]{
						HashAlgorithmTags.SHA256,
						HashAlgorithmTags.SHA1,
						HashAlgorithmTags.SHA384,
						HashAlgorithmTags.SHA512,
						HashAlgorithmTags.SHA224,
				});
		// 3) Request senders add additional checksums to the message (useful when verifying unsigned messages.)
		signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

		// Create a signature on the encryption subkey.
		PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
		// Add metadata to declare its purpose
		enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

		// Objects used to encrypt the secret key.
		PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
		PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

		// bcpg 1.48 exposes this API that includes s2kcount. Earlier versions use a default of 0x60.
		PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, s2kcount)).build(pass.toCharArray());

		// Finally, create the keyring itself. The constructor takes parameters that allow it to generate the self signature.
		PGPKeyRingGenerator keyRingGen =
				new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign,
						id, sha1Calc, signhashgen.generate(), null,
						new BcPGPContentSignerBuilder(rsakp_sign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), pske);

		// Add our encryption subkey, together with its signature.
		keyRingGen.addSubKey(rsakp_enc, enchashgen.generate(), null);
		return keyRingGen;
	}

	@Override
	protected Object retrieveObjectForSampleConfig()
	{
		return new PGPEncryptService();
	}
}
