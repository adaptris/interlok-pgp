package com.adaptris.security.pgp;

public class PGPSignatureTests extends PGPTests
{

	@Override
	protected Object retrieveObjectForSampleConfig()
	{
		return new PGPSignService();
	}
}
