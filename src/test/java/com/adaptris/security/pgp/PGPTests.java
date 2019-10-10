package com.adaptris.security.pgp;

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
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
		kpg.initialize(1024);
		KeyPair kp = kpg.generateKeyPair();
		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
		PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kp, new Date());
		privateKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, ID, sha1Calc, null, null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(PASSPHRASE.toCharArray()));
		publicKey = privateKey.getPublicKey();
	}

	protected String getKey(PGPSecretKey key) throws Exception
	{
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		ArmoredOutputStream armored = new ArmoredOutputStream(keyBytes);
		key.encode(armored);
		armored.close();
		return keyBytes.toString();
	}

	protected String getKey(PGPPublicKey key) throws Exception
	{
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		ArmoredOutputStream armored = new ArmoredOutputStream(keyBytes);
		key.encode(armored);
		armored.close();
		return keyBytes.toString();
	}
}
