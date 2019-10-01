package com.adaptris.security.pgp;

import com.adaptris.core.ServiceCase;

public class PGPEncryptTest extends ServiceCase
{
	/*
	 * We will need a key (hopefully BC has an example; doesn't matter
	 * if it's created new each time and just stored in memory).
	 *
	 * We can probably combine the encrypt and decrypt tests to just a
	 * single test that calls both services and asserts that what comes
	 * out the end is the same as what goes in the beginning.
	 */

	@Override
	protected Object retrieveObjectForSampleConfig()
	{
		return new PGPEncryptService();
	}
}
