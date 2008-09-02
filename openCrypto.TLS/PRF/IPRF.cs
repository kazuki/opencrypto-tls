namespace openCrypto.TLS.PRF
{
	interface IPRF
	{
		byte[] Compute (int bytes, byte[] secret, string label, byte[][] seeds);

		void HandshakeHashInitialize ();
		void HandshakeHashTransformBlock (byte[] buffer, int offset, int length);
		void HandshakeHashTransformFinished (bool senderIsServer);
		byte[] GetHandshakeHash ();
	}
}
