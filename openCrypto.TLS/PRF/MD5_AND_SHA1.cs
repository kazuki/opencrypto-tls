using System;
using System.Security.Cryptography;

namespace openCrypto.TLS.PRF
{
	class MD5_AND_SHA1 : IPRF
	{
		MD5CryptoServiceProvider _md5 = new MD5CryptoServiceProvider ();
		SHA1Managed _sha1 = new SHA1Managed ();

		public byte[] Compute (int bytes, byte[] secret, string label, byte[][] seeds)
		{
			/* SEEDSを再構成 */
			byte[][] new_seeds = new byte[seeds.Length + 1][];
			new_seeds[0] = System.Text.Encoding.ASCII.GetBytes (label);
			for (int i = 0; i < seeds.Length; i ++)
				new_seeds[i + 1] = seeds[i];

			/* secretを分割 */
			byte[] S1 = new byte[secret.Length >> 1];
			byte[] S2 = new byte[secret.Length >> 1];
			Buffer.BlockCopy (secret, 0, S1, 0, S1.Length);
			Buffer.BlockCopy (secret, S1.Length, S2, 0, S2.Length);

			/* P_SHA1とP_MD5を計算 */
			byte[] pSHA1, pMD5;
			using (HMACSHA1 hmacSHA1 = new HMACSHA1 (S2, true))
			using (HMACMD5 hmacMD5 = new HMACMD5 (S1)) {
				pSHA1 = Compute_PHash (bytes, new_seeds, hmacSHA1, 20);
				pMD5 = Compute_PHash (bytes, new_seeds, hmacMD5, 16);
			}

			/* PRFを算出 */
			byte[] prf = new byte[bytes];
			for (int i = 0; i < prf.Length; i++)
				prf[i] = (byte)(pSHA1[i] ^ pMD5[i]);
			return prf;
		}

		static byte[] Compute_PHash (int bytes, byte[][] seeds, HMAC hmac, int blockSize)
		{
			int blocks = (bytes / blockSize) + (bytes % blockSize == 0 ? 0 : 1);
			byte[] ret = new byte[blockSize * blocks];
			byte[] prev = null;

			for (int i = 0; i < blocks; i++) {
				hmac.Initialize ();
				if (prev == null) {
					for (int q = 0; q < seeds.Length; q ++)
						hmac.TransformBlock (seeds[q], 0, seeds[q].Length, seeds[q], 0);
				} else {
					hmac.TransformBlock (prev, 0, prev.Length, prev, 0);
				}
				hmac.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
				prev = hmac.Hash;
				hmac.Initialize ();
				hmac.TransformBlock (prev, 0, prev.Length, prev, 0);
				for (int q = 0; q < seeds.Length; q++)
					hmac.TransformBlock (seeds[q], 0, seeds[q].Length, seeds[q], 0);
				hmac.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
				for (int q = 0; q < blockSize; q++)
					ret[i * blockSize + q] = hmac.Hash[q];
			}
			return ret;
		}

		public void HandshakeHashInitialize ()
		{
			_md5.Initialize ();
			_sha1.Initialize ();
		}

		public void HandshakeHashTransformBlock (byte[] buffer, int offset, int length)
		{
			_md5.TransformBlock (buffer, offset, length, buffer, offset);
			_sha1.TransformBlock (buffer, offset, length, buffer, offset);
		}

		public void HandshakeHashTransformFinished ()
		{
			_md5.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
			_sha1.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
		}

		public byte[] GetHandshakeHash ()
		{
			int md5size = _md5.HashSize >> 3;
			int sha1size = _sha1.HashSize >> 3;
			byte[] hash = new byte[md5size + sha1size];
			Buffer.BlockCopy (_md5.Hash, 0, hash, 0, md5size);
			Buffer.BlockCopy (_sha1.Hash, 0, hash, md5size, sha1size);
			return hash;
		}
	}
}
