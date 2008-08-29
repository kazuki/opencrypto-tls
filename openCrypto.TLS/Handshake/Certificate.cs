using System;
using System.Security.Cryptography.X509Certificates;

namespace openCrypto.TLS.Handshake
{
	class Certificate : HandshakeMessage
	{
		X509Certificate[] _certs;

		public Certificate (X509Certificate[] certs) : base (HandshakeType.Certificate)
		{
			_certs = certs;
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			int certBytes = 0;

			// ハンドシェイクヘッダと全certのバイト量を書き込むエリアをスキップ
			int idx = offset + HandshakeHeaderLength + 3;

			for (int i = 0; i < _certs.Length; i++) {
				byte[] raw = _certs[0].GetRawCertData ();
				idx += BitConverterBE.WriteUInt24 ((uint)raw.Length, buffer, idx);
				Buffer.BlockCopy (raw, 0, buffer, idx, raw.Length);
				idx += raw.Length;
				certBytes += 3 + raw.Length;
			}

			// 全certバイト数を書き込む
			BitConverterBE.WriteUInt24 ((uint)certBytes, buffer, offset + HandshakeHeaderLength);

			// ハンドシェイクメッセージサイズを更新し、ヘッダを書き込む
			_length = (uint)(certBytes + 3);
			WriteHandshakeHeader (buffer, offset);

			return (ushort)(idx - offset);
		}
	}
}
