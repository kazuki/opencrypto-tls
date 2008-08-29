using System;

namespace openCrypto.TLS
{
	static class Utility
	{
		public static readonly byte[] EmptyByteArray = new byte[0];
		public static readonly Extension[] EmptyExtensionArray = new Extension[0];

		public static bool IsNeedServerKeyExchangeMessage (KeyExchangeAlgorithm kea)
		{
			return !(kea == KeyExchangeAlgorithm.RSA ||
				kea == KeyExchangeAlgorithm.DH_DSS ||
				kea == KeyExchangeAlgorithm.DH_RSA ||
				kea == KeyExchangeAlgorithm.ECDH_ECDSA ||
				kea == KeyExchangeAlgorithm.ECDH_RSA);
		}

		public static bool Equals (byte[] x, int xOffset, byte[] y, int yOffset, int length)
		{
			for (int i = 0; i < length; i ++)
				if (x[xOffset + i] != y[yOffset + i])
					return false;
			return true;
		}

		public static void Dump (byte[] raw)
		{
			Dump (raw, 0, raw.Length);
		}

		public static void Dump (byte[] raw, int offset, int size)
		{
			int k = offset;
			for (int i = 0; i < size >> 4; i++) {
				for (int q = 0; q < 16 && k < offset + size; q++, k++) {
					Console.Write ("{0:x2} ", raw[k]);
				}
				Console.WriteLine ();
			}
			if (k < offset + size) {
				while (k < offset + size) {
					Console.Write ("{0:x2} ", raw[k++]);
				}
				Console.WriteLine ();
			}
		}
	}
}
