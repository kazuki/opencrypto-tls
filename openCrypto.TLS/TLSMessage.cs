using System;

namespace openCrypto.TLS
{
	abstract class TLSMessage
	{
		protected ContentType _recordType;

		protected TLSMessage (ContentType type)
		{
			_recordType = type;
		}

		public abstract ushort Write (byte[] buffer, int offset);

		public ContentType RecordContentType {
			get { return _recordType; }
		}
	}
}
