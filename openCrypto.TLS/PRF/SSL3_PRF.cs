using System;
using System.Security.Cryptography;

namespace openCrypto.TLS.PRF
{
	class SSL3_PRF : IPRF
	{
		static byte[] SenderIsClient = new byte[] {0x43, 0x4C, 0x4E, 0x54};
		static byte[] SenderIsServer = new byte[] {0x53, 0x52, 0x56, 0x52};

		SHA1 _sha1;
		MD5 _md5;
		SecurityParameters _sparam;

		public SSL3_PRF (SecurityParameters sparam)
		{
			_sparam = sparam;
			_sha1 = new SHA1Managed ();
			_md5 = new MD5CryptoServiceProvider ();
		}

		public byte[] Compute (int bytes, byte[] secret, string label, byte[][] seeds)
		{
			byte[] output = new byte[bytes];
			int odd_bytes = bytes & 0xF;
			int blocks = (bytes >> 4) + (odd_bytes == 0 ? 0 : 1);
			byte ascii = 65; // 'A'
			byte[] buf = new byte[26];
			for (int i = 0; i < blocks; i ++) {
				_sha1.Initialize ();
				_md5.Initialize ();

				for (int k = 0; k <= i; k ++)
					buf[k] = ascii;
				ascii ++;

				_sha1.TransformBlock (buf, 0, i + 1, buf, 0);
				_sha1.TransformBlock (secret, 0, secret.Length, secret, 0);
				for (int k = 0; k < seeds.Length; k ++)
					_sha1.TransformBlock (seeds[k], 0, seeds[k].Length, seeds[k], 0);
				_sha1.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
				byte[] sha1Hash = _sha1.Hash;

				_md5.TransformBlock (secret, 0, secret.Length, secret, 0);
				_md5.TransformBlock (sha1Hash, 0, sha1Hash.Length, sha1Hash, 0);
				_md5.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
				if (i == blocks - 1 && odd_bytes != 0) {
					Buffer.BlockCopy (_md5.Hash, 0, output, i << 4, odd_bytes);
				} else {
					Buffer.BlockCopy (_md5.Hash, 0, output, i << 4, 16);
				}
			}

			return output;
		}

		public void HandshakeHashInitialize ()
		{
			_sha1.Initialize ();
			_md5.Initialize ();
		}

		public void HandshakeHashTransformBlock (byte[] buffer, int offset, int length)
		{
			_sha1.TransformBlock (buffer, offset, length, buffer, offset);
			_md5.TransformBlock (buffer, offset, length, buffer, offset);
		}

		public void HandshakeHashTransformFinished (bool senderIsServer)
		{
			if (senderIsServer) {
				_sha1.TransformBlock (SenderIsServer, 0, SenderIsServer.Length, SenderIsServer, 0);
				_md5.TransformBlock (SenderIsServer, 0, SenderIsServer.Length, SenderIsServer, 0);
			} else {
				_sha1.TransformBlock (SenderIsClient, 0, SenderIsClient.Length, SenderIsClient, 0);
				_md5.TransformBlock (SenderIsClient, 0, SenderIsClient.Length, SenderIsClient, 0);
			}
			_sha1.TransformBlock (_sparam.MasterSecret, 0, _sparam.MasterSecret.Length, _sparam.MasterSecret, 0);
			_md5.TransformBlock (_sparam.MasterSecret, 0, _sparam.MasterSecret.Length, _sparam.MasterSecret, 0);
			byte[] pad = new byte[48];
			for (int i = 0; i < pad.Length; i++)
				pad[i] = 0x36;
			_sha1.TransformBlock (pad, 0, 40, pad, 0);
			_md5.TransformBlock (pad, 0, 48, pad, 0);
			_sha1.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
			_md5.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);

			byte[] sha1hash = (byte[])_sha1.Hash.Clone ();
			byte[] md5hash = (byte[])_md5.Hash.Clone ();
			for (int i = 0; i < pad.Length; i++)
				pad[i] = 0x5c;

			_sha1.Initialize ();
			_md5.Initialize ();
			_sha1.TransformBlock (_sparam.MasterSecret, 0, _sparam.MasterSecret.Length, _sparam.MasterSecret, 0);
			_md5.TransformBlock (_sparam.MasterSecret, 0, _sparam.MasterSecret.Length, _sparam.MasterSecret, 0);
			_sha1.TransformBlock (pad, 0, 40, pad, 0);
			_md5.TransformBlock (pad, 0, 48, pad, 0);
			_sha1.TransformBlock (sha1hash, 0, sha1hash.Length, sha1hash, 0);
			_md5.TransformBlock (md5hash, 0, md5hash.Length, md5hash, 0);
			_sha1.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
			_md5.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
		}

		public byte[] GetHandshakeHash ()
		{
			byte[] sha1hash = _sha1.Hash;
			byte[] md5hash = _md5.Hash;
			byte[] hash = new byte[sha1hash.Length + md5hash.Length];
			Buffer.BlockCopy (md5hash, 0, hash, 0, md5hash.Length);
			Buffer.BlockCopy (sha1hash, 0, hash, md5hash.Length, sha1hash.Length);
			return hash;
		}
	}
}
