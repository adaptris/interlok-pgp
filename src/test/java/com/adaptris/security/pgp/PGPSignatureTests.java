package com.adaptris.security.pgp;

import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.common.ConstantDataInputParameter;
import com.adaptris.core.common.MetadataDataInputParameter;
import com.adaptris.core.common.PayloadStreamInputParameter;
import com.adaptris.core.common.PayloadStreamOutputParameter;
import com.adaptris.core.common.StringPayloadDataInputParameter;
import com.adaptris.core.common.StringPayloadDataOutputParameter;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.fail;

public class PGPSignatureTests extends PGPTests
{
	@Test
	public void testSignatureDetached() throws Exception
	{
		AdaptrisMessage message = newMessage();
		PGPSignService sign = getSignService(privateKey, PASSPHRASE, true, true);

		sign.doService(message);

		message = newMessage(message);
		message.addMetadata("message", MESSAGE);
		PGPVerifyService verify = getVerifyService(publicKey, true);

		verify.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testSignatureDetachedNoArmor() throws Exception
	{
		AdaptrisMessage message = newMessage();
		PGPSignService sign = getSignService(privateKey, PASSPHRASE, true, false);

		sign.doService(message);

		message = newMessage(message);
		message.addMetadata("message", MESSAGE);
		PGPVerifyService verify = getVerifyService(publicKey, true);

		verify.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testSignatureClear() throws Exception
	{
		AdaptrisMessage message = newMessage();
		PGPSignService sign = getSignService(privateKey, PASSPHRASE, false, true);

		sign.doService(message);

		message = newMessage(message);
		PGPVerifyService verify = getVerifyService(publicKey, false);

		verify.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testSignKeyException()
	{
		try
		{
			AdaptrisMessage message = newMessage();
			PGPSignService service = getSignService(privateKey, PASSPHRASE, true, true);
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
			AdaptrisMessage message = newMessage();
			PGPSignService service = getSignService(privateKey, PASSPHRASE, true, true);
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
			AdaptrisMessage message = newMessage(true);
			PGPSignService service = getSignService(privateKey, PASSPHRASE, true, true);
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
			AdaptrisMessage message = newMessage();
			PGPVerifyService service = getVerifyService(publicKey, false);
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
			AdaptrisMessage message = newMessage();
			PGPVerifyService service = getVerifyService(publicKey, false);
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
			AdaptrisMessage message = newMessage();
			PGPVerifyService service = getVerifyService(publicKey, false);
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
			AdaptrisMessage message = newMessage();
			PGPVerifyService service = getVerifyService(publicKey, false);
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
			AdaptrisMessage message = newMessage();
			PGPSignService sign = getSignService(privateKey, PASSPHRASE, true, true);

			sign.doService(message);

			message = newMessage(message);
			message.addMetadata("message", MESSAGE.replace('g', 'z'));
			PGPVerifyService verify = getVerifyService(publicKey, true);

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
			AdaptrisMessage message = newMessage();
			PGPSignService sign = getSignService(privateKey, PASSPHRASE, false, true);

			sign.doService(message);

			byte[] corruptMessage = message.getPayload();
			/* corrupt the message payload to force an error */
			corruptMessage[corruptMessage.length / 2] += 1;
			message.setPayload(corruptMessage);

			message = newMessage(message);
			PGPVerifyService verify = getVerifyService(publicKey, false);

			verify.doService(message);

			fail();
		}
		catch (Exception e)
		{
			/* expected */
		}
	}

	private PGPSignService getSignService(PGPSecretKey key, String passphrase, boolean detached, boolean armor) throws Exception
	{
		PGPSignService service = new PGPSignService();
		service.setPrivateKey(new ConstantDataInputParameter(getKey(key)));
		service.setPassphrase(new ConstantDataInputParameter(passphrase));
		service.setClearText(detached ? new StringPayloadDataInputParameter() : new PayloadStreamInputParameter());
		service.setDetachedSignature(detached);
		service.setArmorEncoding(armor);
		service.setSignature(detached ? new PayloadStreamOutputParameter() : new StringPayloadDataOutputParameter());
		return service;
	}

	private PGPVerifyService getVerifyService(PGPPublicKey key, boolean detached) throws Exception
	{
		PGPVerifyService service = new PGPVerifyService();
		service.setPublicKey(new ConstantDataInputParameter(getKey(key)));
		service.setSignedMessage(detached ? new MetadataDataInputParameter("message") : new PayloadStreamInputParameter());
		service.setSignature(detached ? new PayloadStreamInputParameter() : null);
		service.setOriginalMessage(detached ? new StringPayloadDataOutputParameter() : new PayloadStreamOutputParameter());
		return service;
	}

	@Override
	protected Object retrieveObjectForSampleConfig()
	{
		return new PGPSignService();
	}

    @Override
    public boolean isAnnotatedForJunit4()
    {
        return true;
    }
}
