using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace openCrypto.TLS
{
	class RecordLayer
	{
		Stream _strm;
		bool _ownStrm;
		RecordState _recordType = RecordState.PlainText;
		public const int MaxFragmentSize = 16384; // (2^14
		ProtocolVersion _ver;
		ICryptoTransform _encryptor, _decryptor;
		HMAC _recvHMAC, _sendHMAC;
		ulong _recvSeq = 0, _sendSeq = 0;
		SecurityParameters _sparams;
		List<byte[]> _handshakePackets = new List<byte[]> ();

		const string DEBUG_CATEGORY = "[RecordLayer]";

		// Receive Buffers
		byte[] _headerBuffer = new byte[5];
		byte[] _recvBuffer = new byte[MaxFragmentSize];

		// Send Buffers
		byte[] _sendBuffer = new byte[MaxFragmentSize + 5];

		public RecordLayer (Stream strm, bool owns_stream, SecurityParameters sparams)
		{
			_strm = strm;
			_ownStrm = owns_stream;
			_sparams = sparams;
		}

		public TLSMessage Read ()
		{
			ReadComplete (_headerBuffer, 0, _headerBuffer.Length);
			ContentType type = (ContentType)_headerBuffer[0];
			ProtocolVersion ver;
			ushort length;
			if (type == ContentType.SSL20Compatible) {
				_handshakePackets.Add (new byte[] {_headerBuffer[2], _headerBuffer[3], _headerBuffer[4]});
				
				length = (ushort)(_headerBuffer[1] - 3);
				if (_headerBuffer[2] != 1)
					throw new Exception ();
				ver = (ProtocolVersion)BitConverterBE.ReadUInt16 (_headerBuffer, 3);
			} else {
				ver = (ProtocolVersion)BitConverterBE.ReadUInt16 (_headerBuffer, 1);
				length = BitConverterBE.ReadUInt16 (_headerBuffer, 3);
			}
			if (ver != ProtocolVersion.SSL30 && ver != ProtocolVersion.TLS10 && ver != ProtocolVersion.TLS11 && ver != ProtocolVersion.TLS12) {
				System.Diagnostics.Debug.WriteLine (string.Format ("[RecordLayer] Unknown Version {0:x4}", (ushort)ver), DEBUG_CATEGORY);
				throw new Exception ();
			}
			if (length > MaxFragmentSize)
				throw new Exception ();
			ReadComplete (_recvBuffer, 0, length);

			// SSL2.0互換ClientHelloのみ例外的な処理
			if (type == ContentType.SSL20Compatible) {
				byte[] tmp = new byte[length];
				Buffer.BlockCopy (_recvBuffer, 0, tmp, 0, length);
				_handshakePackets.Add (tmp);
				return Handshake.ClientHello.CreateFromSSL2CompatibleData (ver, _recvBuffer, 0, length);
			}

			if (_recordType == RecordState.PlainText || _recordType == RecordState.CipherTextSendOnly)
				return ReadPlainText (type, ver, 0, length);
			return ReadCipherText (type, ver, 0, length);
		}

		TLSMessage ReadPlainText (ContentType type, ProtocolVersion ver, int offset, ushort length)
		{
			switch (type) {
				case ContentType.Alert:
					return new Alert ((AlertLevel)_recvBuffer[offset], (AlertDescription)_recvBuffer[offset + 1]);
				case ContentType.ChangeCipherSpec:
					return new ChangeCipherSpec ();
				case ContentType.Handshake:
					HandshakeType htype = (HandshakeType)_recvBuffer[offset];
					uint hlength = BitConverterBE.ReadUInt24 (_recvBuffer, offset + 1);
					if (hlength > MaxFragmentSize - 9)
						throw new Exception (); // TODO

					if (htype == HandshakeType.Finished) {
						ComputeHandshakeHash ();
					}
					byte[] temp = new byte[length];
					Buffer.BlockCopy (_recvBuffer, offset, temp, 0, length);
					_handshakePackets.Add (temp);
					return Handshake.HandshakeMessage.Create (htype, _recvBuffer, offset + 4, hlength);
				case ContentType.ApplicationData:
					return new ApplicationData (_recvBuffer, offset, length);
				default:
					throw new Exception ();
			}
		}

		TLSMessage ReadCipherText (ContentType type, ProtocolVersion ver, int offset, ushort length)
		{
			if (ver == ProtocolVersion.TLS11 && ver == ProtocolVersion.TLS12)
				throw new NotImplementedException ();

			Console.WriteLine ("Encrypted");
			Utility.Dump (_recvBuffer, offset, length);

			int decrypted = 0;
			while (decrypted < length) {
				int tmp = _decryptor.TransformBlock (_recvBuffer, offset + decrypted, length - decrypted, _recvBuffer, decrypted);
				if (tmp == 0)
					throw new CryptographicException ();
				decrypted += tmp;
			}
			Console.WriteLine ("Decrypted");
			Utility.Dump (_recvBuffer, 0, length);

			int fragLen = length - _recvBuffer[length - 1] - _sparams.MACLength - 1;
			Console.WriteLine ("Fragment");
			Utility.Dump (_recvBuffer, 0, fragLen);

			Console.WriteLine ("HMAC");
			Utility.Dump (_recvBuffer, fragLen, _sparams.MACLength);

			byte[] temp = new byte[13];
			_recvHMAC.Initialize ();
			BitConverterBE.WriteUInt64 (_recvSeq, temp, 0);
			temp[8] = (byte)type;
			BitConverterBE.WriteUInt16 ((ushort)ver, temp, 9);
			BitConverterBE.WriteUInt16 ((ushort)fragLen, temp, 11);
			_recvHMAC.TransformBlock (temp, 0, temp.Length, temp, 0);
			_recvHMAC.TransformBlock (_recvBuffer, 0, fragLen, _recvBuffer, 0);
			_recvHMAC.TransformFinalBlock (new byte[0], 0, 0);

			Console.WriteLine ("Comaputed HMAC");
			Utility.Dump (_recvHMAC.Hash);

			_recvSeq++;

			return ReadPlainText (type, ver, 0, (ushort)fragLen);
		}

		public void Write (ContentType type, TLSMessage msg)
		{
			_sendBuffer[0] = (byte)type;
			BitConverterBE.WriteUInt16 ((ushort)_ver, _sendBuffer, 1);
			ushort size;
			if (_recordType == RecordState.PlainText || _recordType == RecordState.CipherTextReceiveOnly)
				size = WritePlainMessage (type, msg, 5);
			else
				size = WriteCipherMessage (type, msg);
			BitConverterBE.WriteUInt16 (size, _sendBuffer, 3);
			_strm.Write (_sendBuffer, 0, size + 5);
		}

		public void Write (Handshake.HandshakeMessage msg)
		{
			Write (ContentType.Handshake, msg);
		}

		ushort WriteCipherMessage (ContentType type, TLSMessage msg)
		{
			if (_ver == ProtocolVersion.TLS11 || _ver == ProtocolVersion.TLS12)
				throw new NotImplementedException ();
			int offset = 5;
			int init_offset = 5;
			ushort length = WritePlainMessage (type, msg, offset);

			byte[] temp = new byte[13];
			_sendHMAC.Initialize ();
			BitConverterBE.WriteUInt64 (_sendSeq, temp, 0);
			temp[8] = (byte)type;
			BitConverterBE.WriteUInt16 ((ushort)_ver, temp, 9);
			BitConverterBE.WriteUInt16 ((ushort)length, temp, 11);
			_sendHMAC.TransformBlock (temp, 0, temp.Length, temp, 0);
			_sendHMAC.TransformBlock (_sendBuffer, offset, length, _sendBuffer, offset);
			_sendHMAC.TransformFinalBlock (new byte[0], 0, 0);
			offset += length;
			Buffer.BlockCopy (_sendHMAC.Hash, 0, _sendBuffer, offset, _sparams.MACLength);
			Console.WriteLine ("Record MAC");
			Utility.Dump (_sendBuffer, offset, _sparams.MACLength);
			offset += _sparams.MACLength;
			byte padding_length = (byte)((_sparams.BlockLength - ((length + _sparams.MACLength + 1) % _sparams.BlockLength)) % _sparams.BlockLength);
			for (int i = 0; i < padding_length; i ++)
				_sendBuffer[offset ++] = padding_length;
			_sendBuffer[offset++] = padding_length;
			length += (ushort)(_sparams.MACLength + padding_length + 1);

			int encrypted = 0;
			while (encrypted < length) {
				int tmp = _encryptor.TransformBlock (_sendBuffer, init_offset + encrypted, length - encrypted, _sendBuffer, init_offset + encrypted);
				if (tmp == 0)
					throw new CryptographicException ();
				encrypted += tmp;
			}

			_sendSeq ++;

			return length;
		}

		ushort WritePlainMessage (ContentType type, TLSMessage msg, int offset)
		{
			ushort size = msg.Write (_sendBuffer, offset);

			if (type == ContentType.Handshake) {
				byte[] temp = new byte[size];
				Buffer.BlockCopy (_sendBuffer, offset, temp, 0, size);
				_handshakePackets.Add (temp);
			}

			return size;
		}

		void ReadComplete (byte[] buffer, int offset, int size)
		{
			int read = 0, tmp;
			while (read < size) {
				tmp = _strm.Read (buffer, offset + read, size - read);
				if (tmp <= 0)
					throw new IOException ();
				read += tmp;
			}
		}

		public void EnableReceiveCipher (ICryptoTransform decryptor, HMAC recvHMAC)
		{
			_decryptor = decryptor;
			_recvHMAC = recvHMAC;
			if (_recordType == RecordState.PlainText)
				_recordType = RecordState.CipherTextReceiveOnly;
			else
				_recordType = RecordState.CipherText;
		}

		public void EnableSendCipher (ICryptoTransform encryptor, HMAC sendHMAC)
		{
			_encryptor = encryptor;
			_sendHMAC = sendHMAC;
			if (_recordType == RecordState.PlainText)
				_recordType = RecordState.CipherTextSendOnly;
			else
				_recordType = RecordState.CipherText;
		}

		public void ComputeHandshakeHash ()
		{
			_sparams.PRF.HandshakeHashInitialize ();
			for (int i = 0; i < _handshakePackets.Count; i++)
				_sparams.PRF.HandshakeHashTransformBlock (_handshakePackets[i], 0, _handshakePackets[i].Length);
			_sparams.PRF.HandshakeHashTransformFinished ();
		}

		public ProtocolVersion ProtocolVersion {
			get { return _ver; }
			set { _ver = value;}
		}

		public void Close ()
		{
			_strm.Flush ();
			if (_ownStrm)
				_strm.Close ();
		}

		#region internal use
		enum RecordState
		{
			PlainText,
			CipherTextReceiveOnly,
			CipherTextSendOnly,
			CipherText
		}
		#endregion
	}
}
