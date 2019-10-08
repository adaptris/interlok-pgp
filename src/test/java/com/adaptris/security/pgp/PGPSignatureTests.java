package com.adaptris.security.pgp;

import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
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

public class PGPSignatureTests extends PGPTests
{
	@Test
	public void testSignatureDetached() throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
		PGPSignService sign = getSignService(privateKey, PASSPHRASE, true, true);

		sign.doService(message);

		message = AdaptrisMessageFactory.getDefaultInstance().newMessage(message.getContent());
		message.addMetadata("message", MESSAGE);
		PGPVerifyService verify = getVerifyService(publicKey, true);

		verify.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testSignatureDetachedNoArmor() throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
		PGPSignService sign = getSignService(privateKey, PASSPHRASE, true, false);

		sign.doService(message);

		message = AdaptrisMessageFactory.getDefaultInstance().newMessage(message.getPayload());
		message.addMetadata("message", MESSAGE);
		PGPVerifyService verify = getVerifyService(publicKey, true);

		verify.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testSignatureClear() throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
		PGPSignService sign = getSignService(privateKey, PASSPHRASE, false, true);

		sign.doService(message);

		message = AdaptrisMessageFactory.getDefaultInstance().newMessage(message.getPayload());
		PGPVerifyService verify = getVerifyService(publicKey, false);

		verify.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	@Test
	public void testSignKeyException()
	{
		try
		{
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
			PGPSignService service = getSignService(privateKey, PASSPHRASE,true, true);
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
	public void testSignPassphraseException()
	{
		try
		{
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
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
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(PASSPHRASE);
			PGPSignService service = getSignService(privateKey, PASSPHRASE, true, true);
			service.setPassphrase(new PayloadStreamInputParameter());
			service.setDataToSign(new ConstantDataInputParameter());
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
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
			PGPVerifyService service = getVerifyService(publicKey, false);
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
	public void testVerifySignedMessageException()
	{
		try
		{
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
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
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
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
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
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
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
			PGPSignService sign = getSignService(privateKey, PASSPHRASE, true, true);

			sign.doService(message);

			message = AdaptrisMessageFactory.getDefaultInstance().newMessage(message.getPayload());
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
			AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
			PGPSignService sign = getSignService(privateKey, PASSPHRASE, false, true);

			sign.doService(message);

			byte[] signedMessage = message.getPayload();
			signedMessage[signedMessage.length / 2] += 1;

			message = AdaptrisMessageFactory.getDefaultInstance().newMessage(signedMessage);
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
		service.setKey(new ConstantDataInputParameter(getKey(key)));
		service.setPassphrase(new ConstantDataInputParameter(passphrase));
		service.setDataToSign(detached ? new StringPayloadDataInputParameter() : new PayloadStreamInputParameter());
		service.setDetachedSignature(detached);
		service.setArmorEncoding(armor);
		service.setSignature(detached ? new PayloadStreamOutputParameter() : new StringPayloadDataOutputParameter());
		return service;
	}

	private PGPVerifyService getVerifyService(PGPPublicKey key, boolean detached) throws Exception
	{
		PGPVerifyService service = new PGPVerifyService();
		service.setKey(new ConstantDataInputParameter(getKey(key)));
		service.setSignedMessage(detached ? new MetadataDataInputParameter("message") : new PayloadStreamInputParameter());
		service.setSignature(detached ? new PayloadStreamInputParameter() : null);
		service.setUnsignedMessage(detached ? new StringPayloadDataOutputParameter() : new PayloadStreamOutputParameter());
		return service;
	}

	@Override
	protected Object retrieveObjectForSampleConfig()
	{
		return new PGPSignService();
	}
}
