namespace openCrypto.TLS.Handshake
{
	class ServerHelloDone : HandshakeMessage
	{
		public ServerHelloDone () : base (HandshakeType.ServerHelloDone)
		{
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			return (ushort)WriteHandshakeHeader (buffer, offset);
		}
	}
}
