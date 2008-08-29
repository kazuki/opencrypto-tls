using System;
using System.IO;

namespace openCrypto.TLS.Handshake
{
	abstract class HandshakeMessage : TLSMessage
	{
		protected HandshakeType _type;
		protected uint _length;
		protected const int HandshakeHeaderLength = 4;

		protected HandshakeMessage (HandshakeType type) : base (ContentType.Handshake)
		{
			_type = type;
			_length = 0;
		}

		public static HandshakeMessage Create (HandshakeType type, byte[] buffer, int offset, uint length)
		{
			Console.WriteLine ("[Handshake] Type:{0}, Size:{1}", type, length);
			switch (type) {
				case HandshakeType.ClientHello:
					return new ClientHello (buffer, offset, length);
				case HandshakeType.ClientKeyExchange:
					return new ClientKeyExchange (buffer, offset, length);
				case HandshakeType.Finished:
					return new Finished (buffer, offset, length);
				default:
					Console.WriteLine ("\tNot implemented type");
					return null;
			}
		}

		/// <summary>
		/// ハンドシェイクヘッダを書き込みます
		/// </summary>
		/// <param name="buffer">書き込み先バッファ</param>
		/// <param name="offset">書き込み先バッファの開始位置</param>
		/// <returns>書き込んだバイト数</returns>
		protected int WriteHandshakeHeader (byte[] buffer, int offset)
		{
			buffer[offset] = (byte)_type;
			BitConverterBE.WriteUInt24 (_length, buffer, offset + 1);
			return HandshakeHeaderLength;
		}
	}
}
