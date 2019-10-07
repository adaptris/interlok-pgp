package com.adaptris.security.pgp;

import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.common.ConstantDataInputParameter;
import com.adaptris.core.common.MetadataStreamOutputParameter;
import com.adaptris.core.common.PayloadStreamInputParameter;
import com.adaptris.core.common.StringPayloadDataInputParameter;
import com.adaptris.core.common.StringPayloadDataOutputParameter;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.Assert;

import java.io.ByteArrayOutputStream;

public class PGPSignatureTests extends PGPTests
{
	public void testSignatureDetached() throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
		PGPSignService sign = getSignService(privateKey, PASSPHRASE, true, true);

		sign.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	public void testSignatureClear() throws Exception
	{
		AdaptrisMessage message = AdaptrisMessageFactory.getDefaultInstance().newMessage(MESSAGE);
		PGPSignService sign = getSignService(privateKey, PASSPHRASE, false, true);

		sign.doService(message);

		Assert.assertEquals(MESSAGE, message.getContent());
	}

	private PGPSignService getSignService(PGPSecretKeyRing key, String passphrase, boolean detached, boolean armor) throws Exception
	{
		ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
		ArmoredOutputStream armoredKey = new ArmoredOutputStream(keyBytes);
		key.encode(armoredKey);
		armoredKey.close();

		PGPSignService service = new PGPSignService();
		service.setKey(new ConstantDataInputParameter(keyBytes.toString()));
		service.setPassphrase(new ConstantDataInputParameter(passphrase));
		service.setDataToSign(new PayloadStreamInputParameter());
		service.setDetachedSignature(detached);
		service.setArmorEncoding(armor);
		service.setSignature(detached ? new MetadataStreamOutputParameter("signature") : new StringPayloadDataOutputParameter());
		return service;
	}

	@Override
	protected Object retrieveObjectForSampleConfig()
	{
		return new PGPSignService();
	}
}
