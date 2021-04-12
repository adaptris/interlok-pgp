package com.adaptris.security.pgp;

import com.adaptris.core.MultiPayloadAdaptrisMessage;
import com.adaptris.core.common.ConstantDataInputParameter;
import com.adaptris.core.common.MultiPayloadStreamInputParameter;
import com.adaptris.core.common.MultiPayloadStreamOutputParameter;
import com.adaptris.core.common.MultiPayloadStringInputParameter;
import com.adaptris.core.common.MultiPayloadStringOutputParameter;
import com.adaptris.core.common.PayloadStreamInputParameter;
import com.adaptris.interlok.config.DataInputParameter;
import com.adaptris.interlok.config.DataOutputParameter;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.fail;

public class PGPSignatureTests extends PGPTests
{
	@Test
	public void testSignatureDetached() throws Exception
	{
		MultiPayloadAdaptrisMessage message = newMessage();
		message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
		PGPSignService sign = getSignService(PASSPHRASE, true, true);
		sign.doService(message);

		message = newMessage(message);
		message.addContent(PAYLOAD_PLAINTEXT, MESSAGE);
		message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
		PGPVerifyService verify = getVerifyService(true, true);
		verify.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
	}

	@Test
	public void testSignatureDetachedNoArmor() throws Exception
	{
		MultiPayloadAdaptrisMessage message = newMessage();
		message.addPayload(PAYLOAD_KEY, getKey(privateKey, false));
		PGPSignService sign = getSignService(PASSPHRASE, true, false);
		sign.doService(message);

		message = newMessage(message);
		message.addContent(PAYLOAD_PLAINTEXT, MESSAGE);
		message.addPayload(PAYLOAD_KEY, getKey(publicKey, false));
		PGPVerifyService verify = getVerifyService(true, false);
		verify.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
	}

	@Test
	public void testSignatureClear() throws Exception
	{
		MultiPayloadAdaptrisMessage message = newMessage();
		message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
		PGPSignService sign = getSignService(PASSPHRASE, false, true);
		sign.doService(message);

		message = newMessage(message);
		message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
		PGPVerifyService verify = getVerifyService(false, true);
		verify.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent(PAYLOAD_PLAINTEXT));
	}

	@Test
	public void testSignKeyException()
	{
		try
		{
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
			PGPSignService service = getSignService(PASSPHRASE, true, true);
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
	public void testSignPassphraseException()
	{
		try
		{
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
			PGPSignService service = getSignService(PASSPHRASE, true, true);
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
	public void testSignDataException()
	{
		try
		{
			MultiPayloadAdaptrisMessage message = newMessage(true);
			message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
			PGPSignService service = getSignService(PASSPHRASE, true, true);
			service.setPassphrase(new PayloadStreamInputParameter());
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
	public void testVerifyKeyException()
	{
		try
		{
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
			PGPVerifyService service = getVerifyService(false, true);
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
	public void testVerifySignedMessageException()
	{
		try
		{
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
			PGPVerifyService service = getVerifyService(false, true);
			service.setSignedMessage(new ConstantDataInputParameter());
			service.doService(message);

			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	@Test
	public void testVerifySignatureNullException()
	{
		try
		{
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
			PGPVerifyService service = getVerifyService(false, true);
			service.setSignature(new ConstantDataInputParameter());
			service.doService(message);

			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	@Test
	public void testVerifySignatureEmptyException()
	{
		try
		{
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
			PGPVerifyService service = getVerifyService(false, true);
			service.setSignature(new ConstantDataInputParameter(""));
			service.doService(message);

			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	@Test
	public void testSignatureFailureDetached()
	{
		try
		{
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
			PGPSignService sign = getSignService(PASSPHRASE, true, true);
			sign.doService(message);

			message = newMessage(message);
			message.addMetadata("message", MESSAGE.replace('g', 'z'));
			message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
			PGPVerifyService verify = getVerifyService(true, true);
			verify.doService(message);

			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	@Test
	public void testSignatureFailureClear()
	{
		try
		{
			MultiPayloadAdaptrisMessage message = newMessage();
			message.addPayload(PAYLOAD_KEY, getKey(privateKey, true));
			PGPSignService sign = getSignService(PASSPHRASE, false, true);
			sign.doService(message);

			byte[] corruptMessage = message.getPayload(PAYLOAD_CIPHERTEXT);
			/* corrupt the message payload to force an error */
			corruptMessage[corruptMessage.length / 2] += 1;
			message = newMessage(message);
			message.addPayload(PAYLOAD_CIPHERTEXT, corruptMessage);
			message.addPayload(PAYLOAD_KEY, getKey(publicKey, true));
			PGPVerifyService verify = getVerifyService(false, true);
			verify.doService(message);

			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	private PGPSignService getSignService(String passphrase, boolean detached, boolean armor)
	{
		PGPSignService service = new PGPSignService();
		service.setPrivateKey(getKeyInput(armor));
		service.setPassphrase(new ConstantDataInputParameter(passphrase));
		DataInputParameter plainParam;
		if (detached)
		{
			plainParam = new MultiPayloadStringInputParameter();
			((MultiPayloadStringInputParameter)plainParam).setPayloadId(PAYLOAD_PLAINTEXT);
		}
		else
		{
			plainParam = new MultiPayloadStreamInputParameter();
			((MultiPayloadStreamInputParameter)plainParam).setPayloadId(PAYLOAD_PLAINTEXT);
		}
		service.setClearText(plainParam);
		service.setDetachedSignature(detached);
		service.setArmorEncoding(armor);
		service.setSignature(getCipherOutput(armor));
		return service;
	}

	private PGPVerifyService getVerifyService(boolean detached, boolean armor)
	{
		PGPVerifyService service = new PGPVerifyService();
		service.setPublicKey(getKeyInput(armor));
		MultiPayloadStreamInputParameter originalMessageParam = null;
		if (detached)
		{
			originalMessageParam = new MultiPayloadStreamInputParameter();
			originalMessageParam.setPayloadId(PAYLOAD_PLAINTEXT);
		}
		service.setSignedMessage(detached ? originalMessageParam : getCipherInput(false));
		service.setSignature(detached ? getCipherInput(armor) : null);
		DataOutputParameter plainParam;
		if (detached)
		{
			plainParam = new MultiPayloadStringOutputParameter();
			((MultiPayloadStringOutputParameter)plainParam).setPayloadId(PAYLOAD_PLAINTEXT);
		}
		else
		{
			plainParam = new MultiPayloadStreamOutputParameter();
			((MultiPayloadStreamOutputParameter)plainParam).setPayloadId(PAYLOAD_PLAINTEXT);
		}
		service.setOriginalMessage(plainParam);
		return service;
	}

	@Override
	protected Object retrieveObjectForSampleConfig()
	{
		return getVerifyService(false, true);
	}
}
