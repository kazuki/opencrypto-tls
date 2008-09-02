using System;
using System.Security.Cryptography;

namespace openCrypto.TLS
{
	class SSL3CompatibleHMAC : HMAC
	{
		MACAlgorithm _mac;
		HashAlgorithm _hash;
		int _padLen;
		static byte[] PAD1, PAD2;

		static SSL3CompatibleHMAC ()
		{
			PAD1 = new byte[48];
			PAD2 = new byte[48];
			for (int i = 0; i < PAD1.Length; i++) {
				PAD1[i] = 0x36;
				PAD2[i] = 0x5c;
			}
		}

		public SSL3CompatibleHMAC (MACAlgorithm algo, byte[] secret)
		{
			_mac = algo;
			switch (algo) {
				case MACAlgorithm.HMAC_MD5:
					_hash = new MD5CryptoServiceProvider ();
					HashSizeValue = 128;
					_padLen = 48;
					break;
				case MACAlgorithm.HMAC_SHA1:
					_hash = new SHA1Managed ();
					HashSizeValue = 160;
					_padLen = 40;
					break;
				default:
					// SSL3はMD5 or SHA1のみ
					throw new Exception ();
			}
			KeyValue = (byte[])secret.Clone ();
		}

		public override void Initialize ()
		{
			_hash.Initialize ();
			_hash.TransformBlock (KeyValue, 0, KeyValue.Length, KeyValue, 0);
			_hash.TransformBlock (PAD1, 0, _padLen, PAD1, 0);
		}

		protected override void HashCore (byte[] rgb, int ib, int cb)
		{
			_hash.TransformBlock (rgb, ib, cb, rgb, ib);
		}

		protected override byte[] HashFinal ()
		{
			_hash.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
			byte[] hash = _hash.Hash;

			using (HashAlgorithm hashAlgo = (_mac == MACAlgorithm.HMAC_MD5 ? (HashAlgorithm)new MD5CryptoServiceProvider () : (HashAlgorithm)new SHA1Managed ())) {
				hashAlgo.Initialize ();
				hashAlgo.TransformBlock (KeyValue, 0, KeyValue.Length, KeyValue, 0);
				hashAlgo.TransformBlock (PAD2, 0, _padLen, PAD2, 0);
				hashAlgo.TransformBlock (hash, 0, hash.Length, hash, 0);
				hashAlgo.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
				hash = (byte[])hashAlgo.Hash.Clone ();
			}
			return hash;
		}
	}
}
