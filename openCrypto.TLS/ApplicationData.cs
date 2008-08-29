using System;
using System.Collections.Generic;
using System.Text;

namespace openCrypto.TLS
{
	class ApplicationData : TLSMessage
	{
		byte[] _buffer;

		public ApplicationData (byte[] buffer, int offset, int size) : base (ContentType.ApplicationData)
		{
			_buffer = new byte[size];
			Buffer.BlockCopy (buffer, offset, _buffer, 0, size);
		}

		public byte[] Data {
			get { return _buffer; }
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			Buffer.BlockCopy (_buffer, 0, buffer, offset, _buffer.Length);
			return (ushort)_buffer.Length;
		}
	}
}
