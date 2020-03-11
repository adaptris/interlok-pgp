package com.adaptris.security.pgp;

import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.MultiPayloadAdaptrisMessage;
import com.adaptris.core.common.*;
import com.adaptris.interlok.config.DataInputParameter;
import com.adaptris.interlok.config.DataOutputParameter;
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
		MultiPayloadAdaptrisMessage message = newMessage();
		message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
		PGPEncryptService encrypt = getEncryptService(true, true);
		encrypt.doService(message);

		message = newMessage(message);
		message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
		PGPDecryptService decrypt = getDecryptService(PASSPHRASE, true);
		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
	}

	@Test
	public void testWorkflowNonArmored() throws Exception
	{
		MultiPayloadAdaptrisMessage message = newMessage();
		message.addPayload(PAYLOAD_KEY, getKey(publicKey, false));
		PGPEncryptService encrypt = getEncryptService(false, true);
		encrypt.doService(message);

		message = newMessage(message);
		message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
		PGPDecryptService decrypt = getDecryptService(PASSPHRASE, false);
		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
	}

	@Test
	public void testWorkflowNoIntegrity() throws Exception
	{
		MultiPayloadAdaptrisMessage message = newMessage();
		message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
		PGPEncryptService encrypt = getEncryptService(true, false);
		encrypt.doService(message);

		message = newMessage(message);
		message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
		PGPDecryptService decrypt = getDecryptService(PASSPHRASE, true);
		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
	}

	@Test
	public void testWorkflowNoArmorOrIntegrity() throws Exception
	{
		MultiPayloadAdaptrisMessage message = newMessage();
		message.addPayload(PAYLOAD_KEY, getKey(publicKey, false));
		PGPEncryptService encrypt = getEncryptService(false, false);
		encrypt.doService(message);

		message = newMessage(message);
		message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
		PGPDecryptService decrypt = getDecryptService(PASSPHRASE, false);
		decrypt.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
	}

	@Test
	public void testEncryptionKeyException()
	{
		try
		{
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(publicKey, false));
			PGPEncryptService service = getEncryptService(false, false);
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
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(publicKey, false));
			PGPEncryptService service = getEncryptService(false, false);
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
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
			PGPDecryptService service = getDecryptService(PASSPHRASE, false);
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
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
			PGPEncryptService encrypt = getEncryptService(true, true);
			encrypt.doService(message);

			message = newMessage(message);
			/* recall setUp to get a new/wrong private key */
			setUp();
			message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
			PGPDecryptService decrypt = getDecryptService(PASSPHRASE, false);
			MultiPayloadByteArrayInputParameter passParam = new MultiPayloadByteArrayInputParameter();
			passParam.setPayloadId(PASSPHRASE);
			message.addPayload(PASSPHRASE, PASSPHRASE.getBytes());
			decrypt.setPassphrase(passParam);
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
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
			PGPDecryptService service = getDecryptService(PASSPHRASE, false);
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
			MultiPayloadAdaptrisMessage message = newMessage(true);
			message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
			PGPDecryptService service = getDecryptService(PASSPHRASE, false);
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

	private PGPEncryptService getEncryptService(boolean armor, boolean integrity) throws Exception
	{
		PGPEncryptService service = new PGPEncryptService();
		service.setPublicKey(getKeyInput(armor));
		MultiPayloadStringInputParameter clearParam = new MultiPayloadStringInputParameter();
		clearParam.setPayloadId(PAYLOAD_PLAINTEXT);
		service.setClearText(clearParam);
		service.setCipherText(getCipherOutput(armor));
		service.setArmorEncoding(armor);
		service.setIntegrityCheck(integrity);
		return service;
	}

	private PGPDecryptService getDecryptService(String passphrase, boolean armor) throws Exception
	{
		PGPDecryptService service = new PGPDecryptService();
		service.setPrivateKey(getKeyInput(armor));
		service.setPassphrase(new ConstantDataInputParameter(passphrase));
		service.setCipherText(getCipherInput(armor));
		MultiPayloadStringOutputParameter plainParam = new MultiPayloadStringOutputParameter();
		plainParam.setPayloadId(PAYLOAD_PLAINTEXT);
		service.setClearText(plainParam);
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
