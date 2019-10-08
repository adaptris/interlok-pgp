package com.adaptris.security.pgp;

import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.common.ConstantDataInputParameter;
import com.adaptris.core.common.PayloadStreamInputParameter;
import com.adaptris.core.common.PayloadStreamOutputParameter;
import com.adaptris.core.common.StringPayloadDataInputParameter;
import com.adaptris.core.common.StringPayloadDataOutputParameter;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayOutputStream;

public class PGPEncryptionTests extends PGPTests
{
	@Test
	public void testEntireWorkflow() throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
		PGPEncryptService encrypt = getEncryptService(publicKey, true, true);

		encrypt.doService(message);

		message = AdaptrisMessageFactory.getDefaultInstance().newMessage(message.getPayload());
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE, true);

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
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE, false);

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
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE, true);

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
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE, false);

		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testEncryptionKeyException()
	{
		try
		{
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
			PGPEncryptService service = getEncryptService(publicKey, false, false);
			service.setKey(new ConstantDataInputParameter());
			service.doService(message);
			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	@Test
	public void testEncryptionDataException()
	{
		try
		{
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
			PGPEncryptService service = getEncryptService(publicKey, false, false);
			service.setClearText(new ConstantDataInputParameter());
			service.doService(message);
			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	@Test
	public void testDecryptionKeyParameterException()
	{
		try
		{
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
			PGPDecryptService service = getDecryptService(privateKey, PASSPHRASE, false);
			service.setKey(new ConstantDataInputParameter());
			service.doService(message);
			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	@Test
	public void testDecryptionWrongKeyException()
	{
		try
		{
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
			PGPEncryptService encrypt = getEncryptService(publicKey, true, true);

			encrypt.doService(message);

			message = AdaptrisMessageFactory.getDefaultInstance().newMessage(message.getPayload());
			/* recall setUp to get a new/wrong private key */
			setUp();
			PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE, false);

			decrypt.doService(message);
			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	@Test
	public void testDecryptionPassphraseException()
	{
		try
		{
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
			PGPDecryptService service = getDecryptService(privateKey, PASSPHRASE, false);
			service.setPassphrase(new ConstantDataInputParameter());
			service.doService(message);
			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	@Test
	public void testDecryptionDataException()
	{
		try
		{
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(PASSPHRASE);
			PGPDecryptService service = getDecryptService(privateKey, PASSPHRASE, false);
			service.setPassphrase(new PayloadStreamInputParameter());
			service.setCipherText(new ConstantDataInputParameter());
			service.doService(message);
			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	private PGPEncryptService getEncryptService(PGPPublicKey key, boolean armor, boolean integrity) throws Exception
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

	private PGPDecryptService getDecryptService(PGPSecretKey key, String passphrase, boolean armor) throws Exception
	{
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		ArmoredOutputStream armoredKey = new ArmoredOutputStream(keyBytes);
		key.encode(armoredKey);
		armoredKey.close();

		PGPDecryptService service = new PGPDecryptService();
		service.setKey(new ConstantDataInputParameter(keyBytes.toString()));
		service.setPassphrase(new ConstantDataInputParameter(passphrase));
		service.setCipherText(armor ? new StringPayloadDataInputParameter() : new PayloadStreamInputParameter());
		service.setClearText(new StringPayloadDataOutputParameter());
		return service;
	}

	@Override
	protected Object retrieveObjectForSampleConfig()
	{
		return new PGPEncryptService();
	}
}
