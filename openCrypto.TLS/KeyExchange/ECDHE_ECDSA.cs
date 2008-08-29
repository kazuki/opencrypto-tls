using System;
using System.Security.Cryptography;
using openCrypto.EllipticCurve.KeyAgreement;
using openCrypto.EllipticCurve.Signature;

namespace openCrypto.TLS.KeyExchange
{
	class ECDHE_ECDSA : IKeyExchange
	{
		ECDiffieHellman _ecdh;
		ECDSA _ecdsa;

		public ECDHE_ECDSA (ECDSA ecdsa)
		{
			_ecdh = new ECDiffieHellman (openCrypto.EllipticCurve.ECDomainNames.secp256r1);
			_ecdh.KDF = null;
			_ecdsa = ecdsa;
		}

		public int CreateServerKeyExchangeParams (byte[] params_buffer, int offset)
		{
			int baseOffset = offset;
			byte[] pub = _ecdh.Parameters.ExportPublicKey (false);
			params_buffer[offset++] = (byte)ECCurveType.NamedCurve;
			offset += BitConverterBE.WriteUInt16 ((ushort)NamedCurve.secp256r1, params_buffer, offset);
			params_buffer[offset++] = (byte)pub.Length;
			Buffer.BlockCopy (pub, 0, params_buffer, offset, pub.Length);
			return offset - baseOffset + pub.Length;
		}

		public int CreateServerKeyExchangeSign (SecurityParameters sparams, byte[] params_buffer, int params_offset, int params_length, byte[] sign_buffer, int sign_offset)
		{
			byte[] hash;
			using (SHA1Managed sha1 = new SHA1Managed ()) {
				sha1.Initialize ();
				sha1.TransformBlock (sparams.ClientRandom, 0, sparams.ClientRandom.Length, sparams.ClientRandom, 0);
				sha1.TransformBlock (sparams.ServerRandom, 0, sparams.ServerRandom.Length, sparams.ServerRandom, 0);
				sha1.TransformBlock (params_buffer, params_offset, params_length, params_buffer, params_offset);
				sha1.TransformFinalBlock (Utility.EmptyByteArray, 0, 0);
				hash = sha1.Hash;
			}

			// 署名
			byte[] sign = _ecdsa.SignHash (hash);
			
			// DER形式に変換
			// TODO: 400bit以上の署名サイズに対応させる
			byte der_len = (byte)(sign.Length + 6);
			byte int_len = (byte)(sign.Length >> 1);
			sign_buffer[sign_offset + 0] = 0x30;
			sign_buffer[sign_offset + 1] = (byte)(der_len - 2);
			sign_buffer[sign_offset + 2] = 0x02;
			sign_buffer[sign_offset + 3] = int_len;
			Buffer.BlockCopy (sign, 0, sign_buffer, sign_offset + 4, int_len);
			sign_offset += int_len + 4;
			sign_buffer[sign_offset + 0] = 0x02;
			sign_buffer[sign_offset + 1] = int_len;
			Buffer.BlockCopy (sign, int_len, sign_buffer, sign_offset + 2, int_len);

			return der_len;
		}

		public void ComputeServerMasterSecret (SecurityParameters sparams, byte[] raw, int offset, int length)
		{
			byte[] pubKey = new byte[raw[offset]];
			Buffer.BlockCopy (raw, offset + 1, pubKey, 0, pubKey.Length);
			byte[] premaster = _ecdh.PerformKeyAgreement (pubKey, 48);
			sparams.MasterSecret = sparams.PRF.Compute (48, premaster, "master secret", new byte[][] {sparams.ClientRandom, sparams.ServerRandom});
		}
	}
}
