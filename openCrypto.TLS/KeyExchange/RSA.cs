using System;
using System.Security.Cryptography;

namespace openCrypto.TLS.KeyExchange
{
	class RSA : IKeyExchange
	{
		RSACryptoServiceProvider _rsa;

		public RSA (RSACryptoServiceProvider rsa)
		{
			_rsa = rsa;
		}

		public int CreateServerKeyExchangeParams (byte[] params_buffer, int offset)
		{
			throw new NotSupportedException ();
		}

		public int CreateServerKeyExchangeSign (SecurityParameters sparams, byte[] params_buffer, int params_offset, int params_length, byte[] sign_buffer, int sign_offset)
		{
			throw new NotSupportedException ();
		}

		public void ComputeServerMasterSecret (SecurityParameters sparams, byte[] raw, int offset, int length)
		{
			ushort encryptedLength = BitConverterBE.ReadUInt16 (raw, offset);
			if (encryptedLength > length - 2) {
				encryptedLength = (ushort)length;
			} else {
				offset += 2;
			}
			byte[] encrypted = new byte[encryptedLength];
			Buffer.BlockCopy (raw, offset, encrypted, 0, encryptedLength);
			byte[] decrypted = _rsa.Decrypt (encrypted, false);
			sparams.SetupMasterSecret (decrypted);
		}
	}
}
