using System;

namespace openCrypto.TLS.Handshake
{
	class ClientKeyExchange : HandshakeMessage
	{
		byte[] _ss_raw;
		int _ss_offset, _ss_length;

		public ClientKeyExchange (byte[] buffer, int offset, uint length) : base (HandshakeType.ClientKeyExchange)
		{
			_ss_raw = buffer;
			_ss_offset = offset;
			_ss_length = (int)length;
		}

		public void ComputeServerMasterSecret (SecurityParameters sparams)
		{
			sparams.KeyExchanger.ComputeServerMasterSecret (sparams, _ss_raw, _ss_offset, _ss_length);
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			throw new NotImplementedException ();
		}
	}
}
