using System;

namespace openCrypto.TLS
{
	public static class BitConverterBE
	{
		public static uint ReadUInt32AndMoveOffset (byte[] buffer, ref int offset)
		{
			uint ret = (uint)((((uint)buffer[offset]) << 24) | (((uint)buffer[offset + 1]) << 16) |
				(((uint)buffer[offset + 2]) << 8) | buffer[offset + 3]);
			offset += 4;
			return ret;
		}

		public static uint ReadUInt24AndMoveOffset (byte[] buffer, ref int offset)
		{
			uint ret = (uint)((((uint)buffer[offset]) << 16) | (((uint)buffer[offset + 1]) << 8) | buffer[offset + 2]);
			offset += 3;
			return ret;
		}

		public static ushort ReadUInt16AndMoveOffset (byte[] buffer, ref int offset)
		{
			ushort ret = (ushort)((((ushort)buffer[offset]) << 8) | buffer[offset + 1]);
			offset += 2;
			return ret;
		}

		public static uint ReadUInt32 (byte[] buffer, int offset)
		{
			return (uint)((((uint)buffer[offset]) << 24) | (((uint)buffer[offset + 1]) << 16) |
				(((uint)buffer[offset + 2]) << 8) | buffer[offset + 3]);
		}

		public static uint ReadUInt24 (byte[] buffer, int offset)
		{
			return (uint)((((uint)buffer[offset]) << 16) | (((uint)buffer[offset + 1]) << 8) | buffer[offset + 2]);
		}

		public static ushort ReadUInt16 (byte[] buffer, int offset)
		{
			return (ushort)((((ushort)buffer[offset]) << 8) | buffer[offset + 1]);
		}

		public static int WriteUInt16 (ushort value, byte[] buffer, int offset)
		{
			buffer[offset] = (byte)(value >> 8);
			buffer[offset + 1] = (byte)value;
			return 2;
		}

		public static int WriteUInt24 (uint value, byte[] buffer, int offset)
		{
			buffer[offset] = (byte)(value >> 16);
			buffer[offset + 1] = (byte)(value >> 8);
			buffer[offset + 2] = (byte)value;
			return 3;
		}

		public static int WriteUInt32 (uint value, byte[] buffer, int offset)
		{
			buffer[offset] = (byte)(value >> 24);
			buffer[offset + 1] = (byte)(value >> 16);
			buffer[offset + 2] = (byte)(value >> 8);
			buffer[offset + 3] = (byte)value;
			return 4;
		}

		public static int WriteUInt64 (ulong value, byte[] buffer, int offset)
		{
			buffer[offset] = (byte)(value >> 56);
			buffer[offset + 1] = (byte)(value >> 48);
			buffer[offset + 2] = (byte)(value >> 40);
			buffer[offset + 3] = (byte)(value >> 32);
			buffer[offset + 4] = (byte)(value >> 24);
			buffer[offset + 5] = (byte)(value >> 16);
			buffer[offset + 6] = (byte)(value >> 8);
			buffer[offset + 7] = (byte)value;
			return 8;
		}
	}
}
