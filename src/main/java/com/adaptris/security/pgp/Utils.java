package com.adaptris.security.pgp;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

class Utils
{
	private static final int READ_AHEAD = 60;

	/**
	 * Obtains a stream that can be used to read PGP data from the provided stream.
	 * <p>
	 * If the initial bytes of the underlying stream are binary PGP encodings, then the stream will
	 * be returned directly, otherwise an {@link ArmoredInputStream} is used to wrap the provided
	 * stream and remove ASCII-Armored encoding.
	 * </p>
	 *
	 * @param in the stream to be checked and possibly wrapped.
	 * @return a stream that will return PGP binary encoded data.
	 * @throws IOException if an error occurs reading the stream, or initialising the
	 *                     {@link ArmoredInputStream}.
	 */
	static InputStream getDecoderStream(InputStream in) throws IOException
	{
		if (!in.markSupported())
		{
			in = new BufferedInputStreamExt(in);
		}
		in.mark(READ_AHEAD);
		int ch = in.read();
		if ((ch & 0x80) != 0)
		{
			in.reset();
			return in;
		}
		else
		{
			if (!isPossiblyBase64(ch))
			{
				in.reset();
				return new ArmoredInputStream(in);
			}
			byte[] buf = new byte[READ_AHEAD];
			int count = 1;
			int index = 1;
			buf[0] = (byte) ch;
			while (count != READ_AHEAD && (ch = in.read()) >= 0)
			{
				if (!isPossiblyBase64(ch))
				{
					in.reset();
					return new ArmoredInputStream(in);
				}
				if (ch != '\n' && ch != '\r')
				{
					buf[index++] = (byte) ch;
				}
				count++;
			}
			in.reset();
			//
			// nothing but new lines, little else, assume regular armoring
			//
			if (count < 4)
			{
				return new ArmoredInputStream(in);
			}
			//
			// test our non-blank data
			//
			byte[] firstBlock = new byte[8];
			System.arraycopy(buf, 0, firstBlock, 0, firstBlock.length);
			try
			{
				byte[] decoded = Base64.decode(firstBlock);
				//
				// it's a base64 PGP block.
				//
				if ((decoded[0] & 0x80) != 0)
				{
					return new ArmoredInputStream(in, false);
				}
				return new ArmoredInputStream(in);
			}
			catch (DecoderException e)
			{
				throw new IOException(e.getMessage());
			}
		}
	}

	private static boolean isPossiblyBase64(int ch)
	{
		return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
				|| (ch >= '0' && ch <= '9') || (ch == '+') || (ch == '/')
				|| (ch == '\r') || (ch == '\n');
	}

	private static class BufferedInputStreamExt extends BufferedInputStream
	{
		BufferedInputStreamExt(InputStream input)
		{
			super (input);
		}
		public synchronized int available() throws IOException
		{
			int result = super.available();
			if (result < 0)
			{
				result = Integer.MAX_VALUE;
			}
			return result;
		}
	}
}
