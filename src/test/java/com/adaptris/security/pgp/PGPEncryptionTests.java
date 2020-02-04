package com.adaptris.security.pgp;

import com.adaptris.core.AdaptrisMessage;
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

import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;

public class PGPEncryptionTests extends PGPTests
{
	@Test
	public void testEntireWorkflow() throws Exception
	{
		AdaptrisMessage message = newMessage();
		PGPEncryptService encrypt = getEncryptService(publicKey, true, true);

		encrypt.doService(message);

		message = newMessage(message);
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE, true);

		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testWorkflowNonArmored() throws Exception
	{
		AdaptrisMessage message = newMessage();
		PGPEncryptService encrypt = getEncryptService(publicKey, false, true);

		encrypt.doService(message);

		message = newMessage(message);
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE, false);

		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testWorkflowNoIntegrity() throws Exception
	{
		AdaptrisMessage message = newMessage();
		PGPEncryptService encrypt = getEncryptService(publicKey, true, false);

		encrypt.doService(message);

		message = newMessage(message);
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE, true);

		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testWorkflowNoArmorOrIntegrity() throws Exception
	{
		AdaptrisMessage message = newMessage();
		PGPEncryptService encrypt = getEncryptService(publicKey, false, false);

		encrypt.doService(message);

		message = newMessage(message);
		PGPDecryptService decrypt = getDecryptService(privateKey, PASSPHRASE, false);

		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testEncryptionKeyException()
	{
		try
		{
			AdaptrisMessage message = newMessage();
			PGPEncryptService service = getEncryptService(publicKey, false, false);
			service.setPublicKey(new ConstantDataInputParameter());
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
			AdaptrisMessage message = newMessage();
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
			AdaptrisMessage message = newMessage();
			PGPDecryptService service = getDecryptService(privateKey, PASSPHRASE, false);
			service.setPrivateKey(new ConstantDataInputParameter());
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
			AdaptrisMessage message = newMessage();
			PGPEncryptService encrypt = getEncryptService(publicKey, true, true);

			encrypt.doService(message);

			message = newMessage(message);
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
			AdaptrisMessage message = newMessage();
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
			AdaptrisMessage message = newMessage(true);
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
		service.setPublicKey(new ConstantDataInputParameter(keyBytes.toString(ENCODING)));
		service.setClearText(new StringPayloadDataInputParameter());
		PayloadStreamOutputParameter streamOutput = new PayloadStreamOutputParameter();
		streamOutput.setContentEncoding(ENCODING);
		service.setCipherText(armor ? new StringPayloadDataOutputParameter() : streamOutput);
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
		service.setPrivateKey(new ConstantDataInputParameter(keyBytes.toString(ENCODING)));
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

    @Override
    public boolean isAnnotatedForJunit4()
    {
        return true;
    }
}
