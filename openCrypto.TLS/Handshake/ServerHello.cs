using System;

namespace openCrypto.TLS.Handshake
{
	class ServerHello : HandshakeMessage
	{
		ProtocolVersion _version;
		byte[] _random;
		byte[] _sessionID;
		CipherSuite _cipherSuite;
		CompressionMethod _compression;
		Extension[] _extensions;

		public ServerHello (ProtocolVersion ver, byte[] random, byte[] sessionID, CipherSuite suite, CompressionMethod compression, Extension[] extensions)
			: base (HandshakeType.ServerHello)
		{
			_version = ver;
			_random = random;
			_sessionID = sessionID;
			_cipherSuite = suite;
			_compression = compression;
			_extensions = extensions;
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			int idx = offset + HandshakeHeaderLength;
			idx += BitConverterBE.WriteUInt16 ((ushort)_version, buffer, idx);
			Buffer.BlockCopy (_random, 0, buffer, idx, _random.Length);
			idx += _random.Length;
			buffer[idx ++] = (byte)_sessionID.Length;
			Buffer.BlockCopy (_sessionID, 0, buffer, idx, _sessionID.Length);
			idx += _sessionID.Length;
			idx += BitConverterBE.WriteUInt16 ((ushort)_cipherSuite, buffer, idx);
			buffer[idx ++] = (byte)_compression;
			if (_extensions != null && _extensions.Length > 0) {
				int idx_backup = idx;

				// Skip
				idx += 2;

				for (int i = 0; i < _extensions.Length; i ++) {
					idx += BitConverterBE.WriteUInt16 ((ushort)_extensions[i].Type, buffer, idx);
					idx += BitConverterBE.WriteUInt16 ((ushort)_extensions[i].Data.Length, buffer, idx);
					Buffer.BlockCopy (_extensions[i].Data, 0, buffer, idx, _extensions[i].Data.Length);
					idx += _extensions[i].Data.Length;
				}

				ushort extBytes = (ushort)(idx - idx_backup - 2);
				BitConverterBE.WriteUInt16 (extBytes, buffer, idx_backup);
			}
			_length = (uint)(idx - offset - HandshakeHeaderLength);
			WriteHandshakeHeader (buffer, offset);
			return (ushort)(idx - offset);
		}
	}
}
