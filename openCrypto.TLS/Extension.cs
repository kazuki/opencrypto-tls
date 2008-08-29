namespace openCrypto.TLS
{
	class Extension
	{
		ExtensionType _type;
		byte[] _data;

		public Extension (ExtensionType type, byte[] data)
		{
			_type = type;
			_data = data;
		}

		public ExtensionType Type {
			get { return _type; }
		}

		public byte[] Data {
			get { return _data; }
		}
	}
}
