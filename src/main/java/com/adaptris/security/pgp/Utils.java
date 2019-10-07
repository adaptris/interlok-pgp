package com.adaptris.security.pgp;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;

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

	static void processLine(OutputStream aOut, PGPSignatureGenerator sGen, byte[] line) throws SignatureException, IOException
	{
		// note: trailing white space needs to be removed from the end of
		// each line for signature calculation RFC 4880 Section 7.1
		int length = Utils.getLengthWithoutWhiteSpace(line);
		if (length > 0)
		{
			sGen.update(line, 0, length);
		}
		aOut.write(line, 0, line.length);
	}

	static void processLine(PGPSignature sig, byte[] line) throws SignatureException, IOException
	{
		int length = Utils.getLengthWithoutWhiteSpace(line);
		if (length > 0)
		{
			sig.update(line, 0, length);
		}
	}

	static int getLengthWithoutWhiteSpace(byte[] line)
	{
		int    end = line.length - 1;
		while (end >= 0 && isWhiteSpace(line[end]))
		{
			end--;
		}
		return end + 1;
	}

	static int getLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
	{
		int    end = line.length - 1;

		while (end >= 0 && isWhiteSpace(line[end]))
		{
			end--;
		}

		return end + 1;
	}

	static byte[] getLineSeparator()
	{
		String nl = Strings.lineSeparator();
		byte[] nlBytes = new byte[nl.length()];

		for (int i = 0; i != nlBytes.length; i++)
		{
			nlBytes[i] = (byte)nl.charAt(i);
		}

		return nlBytes;
	}

	private static boolean isWhiteSpace(byte b)
	{
		return isLineEnding(b) || b == '\t' || b == ' ';
	}

	private static boolean isLineEnding(byte b)
	{
		return b == '\r' || b == '\n';
	}

	static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn) throws IOException
	{
		bOut.reset();
		int lookAhead = -1;
		int ch;
		while ((ch = fIn.read()) >= 0)
		{
			bOut.write(ch);
			if (ch == '\r' || ch == '\n')
			{
				lookAhead = readPassedEOL(bOut, ch, fIn);
				break;
			}
		}
		return lookAhead;
	}

	static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn) throws IOException
	{
		bOut.reset();
		int ch = lookAhead;
		do
		{
			bOut.write(ch);
			if (ch == '\r' || ch == '\n')
			{
				lookAhead = readPassedEOL(bOut, ch, fIn);
				break;
			}
		}
		while ((ch = fIn.read()) >= 0);
		if (ch < 0)
		{
			lookAhead = -1;
		}
		return lookAhead;
	}

	private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn) throws IOException
	{
		int lookAhead = fIn.read();
		if (lastCh == '\r' && lookAhead == '\n')
		{
			bOut.write(lookAhead);
			lookAhead = fIn.read();
		}
		return lookAhead;
	}
}
