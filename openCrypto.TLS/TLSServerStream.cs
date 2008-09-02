using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using openCrypto.TLS.Handshake;

namespace openCrypto.TLS
{
	class TLSServerStream : Stream
	{
		RecordLayer _recordLayer;
		CipherSuiteSelector _selector;
		ConnectionStates _states;
		SecurityParameters _sparams;
		X509Certificate[] _certs;
		AsymmetricAlgorithm _signAlgo;
		byte[] _readBuffer = new byte[RecordLayer.MaxFragmentSize];
		int _readBufferOffset = 0, _readBufferSize = 0;

		public TLSServerStream (Stream baseStream, bool owns_stream, X509Certificate[] certificates, AsymmetricAlgorithm signAlgo, CipherSuiteSelector selector)
		{
			_states = new ConnectionStates ();
			_sparams = _states.SecurityParameters;
			_recordLayer = new RecordLayer (baseStream, owns_stream, _sparams);
			_certs = certificates;
			_signAlgo = signAlgo;
			_selector = selector;
			ProcessHandshake ();
		}

		public override int Read (byte[] buffer, int offset, int count)
		{
			int size = count;
			while (count > 0) {
				if (_readBufferSize == 0) {
					ApplicationData appData = (ApplicationData)_recordLayer.Read ();
					Buffer.BlockCopy (appData.Data, 0, _readBuffer, 0, appData.Data.Length);
					_readBufferOffset = 0;
					_readBufferSize = appData.Data.Length;
				}
				int copySize = (count > _readBufferSize ? _readBufferSize : count);
				Buffer.BlockCopy (_readBuffer, _readBufferOffset, buffer, offset, copySize);
				_readBufferOffset += copySize;
				_readBufferSize -= copySize;
				offset += copySize;
				count -= copySize;
			}
			return size;
		}

		public override void Write (byte[] buffer, int offset, int count)
		{
			for (int i = 0; i < count; i += RecordLayer.MaxFragmentSize) {
				int size = (count - i > RecordLayer.MaxFragmentSize ? RecordLayer.MaxFragmentSize : count - i);
				ApplicationData data = new ApplicationData (buffer, i, size);
				_recordLayer.Write (ContentType.ApplicationData, data);
			}
		}

		public override void Flush ()
		{
		}

		#region Handshake
		void ProcessHandshake ()
		{
			ClientHello clientHello = _recordLayer.Read () as ClientHello;
			if (clientHello == null)
				throw new Exception ();
			Console.WriteLine ("[TLSServer] Receive ClientHello Version: {0}", clientHello.Version);
			Console.WriteLine ("[TLSServer] CipherSuites");
			for (int i = 0; i < clientHello.CipherSuites.Length; i ++)
				Console.WriteLine ("  {0}", clientHello.CipherSuites[i]);
			CipherSuite selected = _selector.Select (clientHello.CipherSuites);
			Console.WriteLine ("[TLSServer] CipherSuite Selected. {0}", selected);
			if (selected == CipherSuite.NONE) {
				// Alertを送るべき？
				throw new Exception ();
			}
			_sparams.SetVersion (clientHello.Version);
			_sparams.SetCipherSuite (selected, _signAlgo);
			_sparams.ClientRandom = clientHello.Random;
			_recordLayer.ProtocolVersion = clientHello.Version;

			byte[] serverRandom = new byte[RandomData.Size];
			Extension[] serverExtensions = new Extension[] {new Extension (ExtensionType.EcPointFormats, new byte[] {1, 0})};
			RandomData.CreateRandomData (serverRandom, 0);
			_sparams.ServerRandom = serverRandom;
			ServerHello serverHello = new ServerHello (clientHello.Version, serverRandom, Utility.EmptyByteArray, selected, CompressionMethod.Null, serverExtensions);
			_recordLayer.Write (serverHello);

			Certificate serverCert = new Certificate (_certs);
			_recordLayer.Write (serverCert);

			if (Utility.IsNeedServerKeyExchangeMessage (_states.SecurityParameters.KeyExchangeAlgorithm)) {
				ServerKeyExchange serverExchange = new ServerKeyExchange (_sparams);
				_recordLayer.Write (serverExchange);
			}

			_recordLayer.Write (new ServerHelloDone ());

			TLSMessage msg = _recordLayer.Read ();
			ClientKeyExchange clientExchange = (ClientKeyExchange)msg;
			clientExchange.ComputeServerMasterSecret (_sparams);
			Console.WriteLine ("MasterSecret");
			Utility.Dump (_sparams.MasterSecret);
			_sparams.ComputeKeyBlock ();

			ChangeCipherSpec changeCipherSpec = (ChangeCipherSpec)_recordLayer.Read ();
			_recordLayer.EnableReceiveCipher (_sparams.CreateServerDecryptor (), _sparams.CreateClientWriteHMAC ());

			Finished finished = (Finished)_recordLayer.Read ();
			Console.WriteLine ("VerifyData");
			Utility.Dump (finished.VerifyData);
			Console.WriteLine ("Computed VerifyData");
			byte[] verifyData = _sparams.ComputeFinishedVerifyData (false);
			Utility.Dump (verifyData);
			if (!Utility.Equals (finished.VerifyData, 0, verifyData, 0, verifyData.Length))
				throw new Exception ();

			_recordLayer.Write (ContentType.ChangeCipherSpec, new ChangeCipherSpec ());
			_recordLayer.EnableSendCipher (_sparams.CreateServerEncryptor (), _sparams.CreateServerWriteHMAC ());
			_recordLayer.ComputeHandshakeHash (true);
			verifyData = _sparams.ComputeFinishedVerifyData (true);
			Console.WriteLine ("Finished VerifyData");
			Utility.Dump (verifyData);
			finished = new Finished (_recordLayer.ProtocolVersion, verifyData);
			_recordLayer.Write (finished);
		}
		#endregion

		#region Close
		public override void Close ()
		{
			base.Close ();
			if (_recordLayer != null) {
				_recordLayer.Write (ContentType.Alert, new Alert (AlertLevel.Warning, AlertDescription.CloseNotify));
				_recordLayer.Close ();
			}
		}
		#endregion

		#region Misc
		public override bool CanRead
		{
			get { return true; }
		}

		public override bool CanSeek
		{
			get { return false; }
		}

		public override bool CanWrite
		{
			get { return true; }
		}

		public override long Length
		{
			get { throw new NotSupportedException (); }
		}

		public override long Position
		{
			get
			{
				throw new NotSupportedException ();
			}
			set
			{
				throw new NotSupportedException ();
			}
		}

		public override long Seek (long offset, SeekOrigin origin)
		{
			throw new NotSupportedException ();
		}

		public override void SetLength (long value)
		{
			throw new NotSupportedException ();
		}
		#endregion
	}
}
