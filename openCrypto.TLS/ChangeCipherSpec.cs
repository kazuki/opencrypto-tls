namespace openCrypto.TLS
{
	class ChangeCipherSpec : TLSMessage
	{
		static ChangeCipherSpec _instance = new ChangeCipherSpec ();

		ChangeCipherSpec () : base (ContentType.ChangeCipherSpec)
		{
		}

		public static ChangeCipherSpec Instance {
			get { return _instance; }
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			buffer[offset] = 1;
			return 1;
		}
	}
}
