namespace openCrypto.TLS
{
	class Alert : TLSMessage
	{
		AlertLevel _level;
		AlertDescription _desc;

		public Alert (AlertLevel level, AlertDescription desc) : base (ContentType.Alert)
		{
			_level = level;
			_desc = desc;
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			buffer[offset] = (byte)_level;
			buffer[offset + 1] = (byte)_desc;
			return 2;
		}
	}
}
