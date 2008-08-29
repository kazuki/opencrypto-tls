namespace openCrypto.TLS
{
	class ChangeCipherSpec : TLSMessage
	{
		public ChangeCipherSpec () : base (ContentType.ChangeCipherSpec)
		{
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			buffer[offset] = 1;
			return 1;
		}
	}
}
