using System;
using System.Collections.Generic;

namespace openCrypto.TLS.Handshake
{
	class ClientHello : HandshakeMessage
	{
		ProtocolVersion _version;
		byte[] _random;
		byte[] _sessionId;
		CipherSuite[] _cipherSuites;
		CompressionMethod[] _compressions;
		Extension[] _extensions;

		private ClientHello (ProtocolVersion ver) : base (HandshakeType.ClientHello)
		{
			_version = ver;
		}

		public ClientHello (byte[] buffer, int offset, uint length) : base (HandshakeType.ClientHello)
		{
			int idx = offset, end = (int)(offset + length);

			_version = (ProtocolVersion)BitConverterBE.ReadUInt16AndMoveOffset (buffer, ref idx);
			_random = RandomData.ReadRandomData (buffer, idx);
			idx += RandomData.Size;

			if (buffer[idx] > 32)
				throw new FormatException ();
			_sessionId = new byte[buffer[idx]];
			Buffer.BlockCopy (buffer, idx + 1, _sessionId, 0, _sessionId.Length);
			idx += 1 + _sessionId.Length;

			_cipherSuites = new CipherSuite[BitConverterBE.ReadUInt16AndMoveOffset (buffer, ref idx) >> 1];
			for (int i = 0; i < _cipherSuites.Length; i++)
				_cipherSuites[i] = (CipherSuite)BitConverterBE.ReadUInt16AndMoveOffset (buffer, ref idx);

			_compressions = new CompressionMethod[buffer[idx]];
			for (int i = 0; i < _compressions.Length; i++)
				_compressions[i] = (CompressionMethod)buffer[idx + 1 + i];
			idx += 1 + _compressions.Length;

			if (idx < end) {
				int extBytes = BitConverterBE.ReadUInt16AndMoveOffset (buffer, ref idx);
				List<Extension> list = new List<Extension> ();
				while (idx < end) {
					ExtensionType etype = (ExtensionType)BitConverterBE.ReadUInt16 (buffer, idx);
					int esize = BitConverterBE.ReadUInt16 (buffer, idx + 2);
					byte[] edata = new byte[esize];
					Buffer.BlockCopy (buffer, idx + 4, edata, 0, esize);
					list.Add (new Extension (etype, edata));
					idx += 4 + esize;
				}
				_extensions = list.ToArray ();
			} else {
				_extensions = Utility.EmptyExtensionArray;
			}
		}

		public static ClientHello CreateFromSSL2CompatibleData (ProtocolVersion ver, byte[] buffer, int offset, uint length)
		{
			ClientHello msg = new ClientHello (ver);

			int cipherLen = BitConverterBE.ReadUInt16AndMoveOffset (buffer, ref offset) / 3;
			ushort sessionIdLen = BitConverterBE.ReadUInt16AndMoveOffset (buffer, ref offset);
			if (sessionIdLen != 0 && sessionIdLen != 16)
				throw new Exception ();
			ushort challengeLen = BitConverterBE.ReadUInt16AndMoveOffset (buffer, ref offset);
			if (challengeLen < 16)
				throw new Exception ();
			if (challengeLen > RandomData.Size)
				challengeLen =	RandomData.Size;
			msg._cipherSuites = new CipherSuite[cipherLen];
			for (int i = 0; i < cipherLen; i ++)
				msg._cipherSuites[i] = (CipherSuite)BitConverterBE.ReadUInt24AndMoveOffset (buffer, ref offset);
			msg._sessionId = new byte[sessionIdLen];
			Buffer.BlockCopy (buffer, offset, msg._sessionId, 0, sessionIdLen);
			offset += sessionIdLen;
			msg._random = new byte[challengeLen];
			Buffer.BlockCopy (buffer, offset, msg._random, 0, challengeLen);
			return msg;
		}

		public override ushort Write (byte[] buffer, int offset)
		{
			throw new NotSupportedException ();
		}

		#region Properties
		public ProtocolVersion Version {
			get { return _version; }
		}

		public byte[] Random {
			get { return _random; }
		}

		public byte[] SessionID {
			get { return _sessionId; }
		}

		public CipherSuite[] CipherSuites {
			get { return _cipherSuites; }
		}

		public CompressionMethod[] CompressionMethods {
			get { return _compressions; }
		}

		public Extension[] Extensions {
			get { return _extensions; }
		}
		#endregion
	}
}
