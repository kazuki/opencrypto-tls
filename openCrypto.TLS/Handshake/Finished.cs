using System;

namespace openCrypto.TLS.Handshake
{
	class Finished : HandshakeMessage
	{
		byte[] _verifyData;

		public Finished (ProtocolVersion ver, byte[] verifyData) : base (HandshakeType.Finished)
		{
			if (ver == ProtocolVersion.SSL30 && verifyData.Length != 36)
				throw new ArgumentException ();
			if (ver != ProtocolVersion.SSL30 && verifyData.Length != 12)
				throw new ArgumentException ();
			_verifyData = verifyData;
		}

		public Finished (ProtocolVersion ver, byte[] buffer, int offset, uint length) : base (HandshakeType.Finished)
		{
			if (ver == ProtocolVersion.SSL30)
				_verifyData = new byte[36];
			else
				_verifyData = new byte[12];
			Buffer.BlockCopy (buffer, offset, _verifyData, 0, _verifyData.Length);
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			_length = (uint)_verifyData.Length;
			WriteHandshakeHeader (buffer, offset);
			Buffer.BlockCopy (_verifyData, 0, buffer, offset + HandshakeHeaderLength, _verifyData.Length);
			return (ushort)(HandshakeHeaderLength + _verifyData.Length);
		}

		public byte[] VerifyData {
			get { return _verifyData; }
		}
	}
}
