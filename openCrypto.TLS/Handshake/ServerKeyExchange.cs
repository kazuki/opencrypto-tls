using System;
using System.Security.Cryptography;
using openCrypto.TLS.KeyExchange;

namespace openCrypto.TLS.Handshake
{
	class ServerKeyExchange : HandshakeMessage
	{
		SecurityParameters _sparams;

		public ServerKeyExchange (SecurityParameters sparams) : base (HandshakeType.ServerKeyExchange)
		{
			_sparams = sparams;
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			int idx = offset + HandshakeHeaderLength;
			int paramSize = _sparams.KeyExchanger.CreateServerKeyExchangeParams (buffer, idx);
			int signSize = _sparams.KeyExchanger.CreateServerKeyExchangeSign (_sparams, buffer, idx, paramSize, buffer, idx + paramSize + 2);
			BitConverterBE.WriteUInt16 ((ushort)signSize, buffer, idx + paramSize);
			_length = (uint)(paramSize + signSize + 2);
			WriteHandshakeHeader (buffer, offset);
			return (ushort)(_length + HandshakeHeaderLength);
		}
	}
}
