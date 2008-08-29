using System;
using System.Collections.Generic;

namespace openCrypto.TLS
{
	class CipherSuiteInfo
	{
		BulkCipherAlgorithm _bulk_cipher;
		CipherType _cipherType;
		byte _enc_key_length;
		byte _block_length;
		byte _fixed_iv_length;
		byte _record_iv_length;
		MACAlgorithm _mac;
		byte _mac_length;
		byte _mac_key_length;
		KeyExchangeAlgorithm _exchangeAlgo;

		public CipherSuiteInfo (BulkCipherAlgorithm cipher, CipherType cipherType,
			byte encKeyLen, byte blockLen, byte ivLen, byte recordIVLen, MACAlgorithm mac,
			KeyExchangeAlgorithm exchangeAlgo)
		{
			_bulk_cipher = cipher;
			_cipherType = cipherType;
			_enc_key_length = encKeyLen;
			_block_length = blockLen;
			_fixed_iv_length = ivLen;
			_record_iv_length = recordIVLen;
			_mac = mac;
			_exchangeAlgo = exchangeAlgo;
			switch (mac) {
				case MACAlgorithm.HMAC_MD5: _mac_length = _mac_key_length = 16; break;
				case MACAlgorithm.HMAC_SHA1: _mac_length = _mac_key_length = 20; break;
				case MACAlgorithm.HMAC_SHA256: _mac_length = _mac_key_length = 32; break;
				case MACAlgorithm.HMAC_SHA384: _mac_length = _mac_key_length = 48; break;
				case MACAlgorithm.HMAC_SHA512: _mac_length = _mac_key_length = 64; break;
				default: throw new ArgumentOutOfRangeException ();
			}
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

		public KeyExchangeAlgorithm KeyExchangeAlgorithm {
			get { return _exchangeAlgo; }
		}
	}
}
