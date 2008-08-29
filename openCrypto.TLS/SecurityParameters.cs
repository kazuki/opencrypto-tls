using System;
using System.Security.Cryptography;
using openCrypto.TLS.KeyExchange;
using openCrypto.TLS.PRF;

namespace openCrypto.TLS
{
	class SecurityParameters
	{
		#region Variables
		PRFAlgorithm _prfType = PRFAlgorithm.MD5_AND_SHA1;
		BulkCipherAlgorithm _bulk_cipher;
		CipherType _cipherType;
		byte _enc_key_length;
		byte _block_length;
		byte _fixed_iv_length;
		byte _record_iv_length;
		MACAlgorithm _mac;
		byte _mac_length;
		byte _mac_key_length;
		CompressionMethod _compression;
		byte[] _master_secret;
		byte[] _client_random;
		byte[] _server_random;
		KeyExchangeAlgorithm _keyExchange;
		IKeyExchange _keyExchanger;
		IPRF _prf = null;
		SymmetricAlgorithm _symmetricAlgo = null;
		byte[] _client_write_MAC_key;
		byte[] _server_write_MAC_key;
		byte[] _client_write_key;
		byte[] _server_write_key;
		byte[] _client_write_IV;
		byte[] _server_write_IV;
		#endregion

		#region Constructors
		public SecurityParameters ()
		{
		}
		#endregion

		#region Methods
		public void SetCipherSuite (CipherSuite suite, AsymmetricAlgorithm signAlgo)
		{
			CipherSuiteInfo info = SupportedCipherSuites.GetSuiteInfo (suite);
			if (info == null)
				throw new NotSupportedException ();

			_bulk_cipher = info.BulkCipherAlgorithm;
			_cipherType = info.CipherType;
			_enc_key_length = info.EncKeyLength;
			_block_length = info.BlockLength;
			_fixed_iv_length = info.FixedIVLength;
			_record_iv_length = info.RecordIVLength;
			_mac = info.MACAlgorithm;
			_mac_length = info.MACLength;
			_mac_key_length = info.MACKeyLength;
			_keyExchange = info.KeyExchangeAlgorithm;

			// TODO: TLS1.2spec ?
			_prf = new MD5_AND_SHA1 ();

			switch (_keyExchange) {
				case KeyExchangeAlgorithm.ECDHE_ECDSA:
					_keyExchanger = new ECDHE_ECDSA ((openCrypto.EllipticCurve.Signature.ECDSA)signAlgo);
					break;
				default:
					throw new NotImplementedException ();
			}
		}

		public void ComputeKeyBlock ()
		{
			int bytes = (_mac_key_length << 1) + (_enc_key_length << 1) + (_fixed_iv_length << 1);
			byte[] key_block = _prf.Compute (bytes, _master_secret, "key expansion", new byte[][]{_server_random, _client_random});
			Console.WriteLine ("KeyBlock");
			Utility.Dump (key_block);

			_client_write_MAC_key = new byte[_mac_key_length];
			_server_write_MAC_key = new byte[_mac_key_length];
			_client_write_key = new byte[_enc_key_length];
			_server_write_key = new byte[_enc_key_length];
			_client_write_IV = new byte[_fixed_iv_length];
			_server_write_IV = new byte[_fixed_iv_length];

			int idx = 0;
			Buffer.BlockCopy (key_block, idx, _client_write_MAC_key, 0, _mac_key_length);
			idx += _mac_key_length;
			Buffer.BlockCopy (key_block, idx, _server_write_MAC_key, 0, _mac_key_length);
			idx += _mac_key_length;
			Buffer.BlockCopy (key_block, idx, _client_write_key, 0, _enc_key_length);
			idx += _enc_key_length;
			Buffer.BlockCopy (key_block, idx, _server_write_key, 0, _enc_key_length);
			idx += _enc_key_length;
			Buffer.BlockCopy (key_block, idx, _client_write_IV, 0, _fixed_iv_length);
			idx += _fixed_iv_length;
			Buffer.BlockCopy (key_block, idx, _server_write_IV, 0, _fixed_iv_length);
			idx += _fixed_iv_length;
		}

		public HMAC CreateClientWriteHMAC ()
		{
			return CreateHMAC (_client_write_MAC_key);
		}

		public HMAC CreateServerWriteHMAC ()
		{
			return CreateHMAC (_server_write_MAC_key);
		}

		public HMAC CreateHMAC (byte[] key)
		{
			switch (_mac) {
				case MACAlgorithm.HMAC_MD5:
					return new HMACMD5 (key);
				case MACAlgorithm.HMAC_SHA1:
					return new HMACSHA1 (key);
				case MACAlgorithm.HMAC_SHA256:
					return new HMACSHA256 (key);
				case MACAlgorithm.HMAC_SHA384:
					return new HMACSHA384 (key);
				case MACAlgorithm.HMAC_SHA512:
					return new HMACSHA512 (key);
				default:
					throw new Exception ();
			}
		}

		public SymmetricAlgorithm CreateSymmetricAlgorithm ()
		{
			if (_symmetricAlgo == null) {
				switch (_bulk_cipher) {
					case BulkCipherAlgorithm.AES:
						_symmetricAlgo = new System.Security.Cryptography.RijndaelManaged ();
						break;
					default:
						throw new Exception ();
				}
				_symmetricAlgo.KeySize = _enc_key_length << 3;
				_symmetricAlgo.BlockSize = _block_length << 3;
				_symmetricAlgo.Mode = CipherMode.CBC;
				_symmetricAlgo.Padding = PaddingMode.None;
			}
			return _symmetricAlgo;
		}

		public ICryptoTransform CreateServerEncryptor ()
		{
			return CreateSymmetricAlgorithm ().CreateEncryptor (_server_write_key, _server_write_IV);
		}

		public ICryptoTransform CreateServerDecryptor ()
		{
			return CreateSymmetricAlgorithm ().CreateDecryptor (_client_write_key, _client_write_IV);
		}

		public ICryptoTransform CreateClientDecryptor ()
		{
			return CreateSymmetricAlgorithm ().CreateEncryptor (_server_write_key, _server_write_IV);
		}

		public ICryptoTransform CreateClientEncryptor ()
		{
			return CreateSymmetricAlgorithm ().CreateDecryptor (_client_write_key, _client_write_IV);
		}
		#endregion

		#region Properties
		public PRFAlgorithm PRFAlgorithm {
			get { return _prfType; }
			internal set { _prfType = value; }
		}

		public BulkCipherAlgorithm BulkCipherAlgorithm {
			get { return _bulk_cipher; }
		}

		public CipherType CipherType {
			get { return _cipherType; }
		}

		public byte EncKeyLength {
			get { return _enc_key_length; }
		}

		public byte BlockLength {
			get { return _block_length; }
		}

		public byte FixedIVLength {
			get { return _fixed_iv_length; }
		}

		public byte RecordIVLength {
			get { return _record_iv_length; }
		}

		public MACAlgorithm MACAlgorithm {
			get { return _mac; }
		}

		public byte MACLength {
			get { return _mac_length; }
		}

		public byte MACKeyLength {
			get { return _mac_key_length; }
		}

		public CompressionMethod CompressionAlgorithm {
			get { return _compression; }
			internal set { _compression = value; }
		}

		public byte[] MasterSecret {
			get { return _master_secret; }
			internal set {
				if (value.Length != 48)
					throw new ArgumentException ();
				_master_secret = value;
			}
		}

		public byte[] ClientRandom {
			get { return _client_random; }
			internal set {
				if (value.Length != 32)
					throw new ArgumentException ();
				_client_random = value;
			}
		}

		public byte[] ServerRandom {
			get { return _server_random; }
			internal set {
				if (value.Length != 32)
					throw new ArgumentException ();
				_server_random = value;
			}
		}

		public KeyExchangeAlgorithm KeyExchangeAlgorithm {
			get { return _keyExchange; }
		}

		public IKeyExchange KeyExchanger {
			get { return _keyExchanger; }
		}

		public IPRF PRF {
			get { return _prf; }
		}
		#endregion
	}
}
