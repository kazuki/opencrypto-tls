using System;

namespace openCrypto.TLS
{
	static class RandomData
	{
		static long UnixTimeStart = new DateTime (1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;
		public const int Size = 32;
		static byte[] _randBuffer = new byte[28];

		public static void CreateRandomData (byte[] buffer, int offset)
		{
			uint unixTime = (uint)((DateTime.UtcNow.Ticks - UnixTimeStart) / TimeSpan.TicksPerSecond);
			BitConverterBE.WriteUInt32 (unixTime, buffer, offset);
			lock (_randBuffer) {
				RNG.GetBytes (_randBuffer);
				Buffer.BlockCopy (_randBuffer, 0, buffer, offset + 4, _randBuffer.Length);
			}
		}

		public static byte[] ReadRandomData (byte[] buffer, int offset)
		{
			byte[] temp = new byte[Size];
			Buffer.BlockCopy (buffer, offset, temp, 0, Size);
			return temp;
		}
	}
}
