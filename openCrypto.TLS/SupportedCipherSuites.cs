using System;
using System.Collections.Generic;
using System.Text;

namespace openCrypto.TLS
{
	public static class SupportedCipherSuites
	{
		public static CipherSuite[] SupportedSuites = new CipherSuite[] {
			//CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			//CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			//CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
			//CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
			//CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
			CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
			//CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
			//CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
			//CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
			//CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA
		};

		static Dictionary<CipherSuite, CipherSuiteInfo> _list = new Dictionary<CipherSuite,CipherSuiteInfo> ();

		static SupportedCipherSuites ()
		{
			_list.Add (CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				new CipherSuiteInfo (BulkCipherAlgorithm.AES, CipherType.Block, 32, 16, 16, 16, MACAlgorithm.HMAC_SHA1, KeyExchangeAlgorithm.ECDHE_ECDSA));
			_list.Add (CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				new CipherSuiteInfo (BulkCipherAlgorithm.AES, CipherType.Block, 16, 16, 16, 16, MACAlgorithm.HMAC_SHA1, KeyExchangeAlgorithm.ECDHE_ECDSA));
			_list.Add (CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
				new CipherSuiteInfo (BulkCipherAlgorithm.AES, CipherType.Block, 32, 16, 16, 16, MACAlgorithm.HMAC_SHA256, KeyExchangeAlgorithm.RSA));
			_list.Add (CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
				new CipherSuiteInfo (BulkCipherAlgorithm.AES, CipherType.Block, 32, 16, 16, 16, MACAlgorithm.HMAC_SHA1, KeyExchangeAlgorithm.RSA));
			_list.Add (CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
				new CipherSuiteInfo (BulkCipherAlgorithm.AES, CipherType.Block, 16, 16, 16, 16, MACAlgorithm.HMAC_SHA256, KeyExchangeAlgorithm.RSA));
			_list.Add (CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
				new CipherSuiteInfo (BulkCipherAlgorithm.AES, CipherType.Block, 16, 16, 16, 16, MACAlgorithm.HMAC_SHA1, KeyExchangeAlgorithm.RSA));
			_list.Add (CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
				new CipherSuiteInfo (BulkCipherAlgorithm.AES, CipherType.Block, 32, 16, 16, 16, MACAlgorithm.HMAC_SHA256, KeyExchangeAlgorithm.DHE_DSS));
			_list.Add (CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
				new CipherSuiteInfo (BulkCipherAlgorithm.AES, CipherType.Block, 32, 16, 16, 16, MACAlgorithm.HMAC_SHA1, KeyExchangeAlgorithm.DHE_DSS));
			_list.Add (CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
				new CipherSuiteInfo (BulkCipherAlgorithm.AES, CipherType.Block, 16, 16, 16, 16, MACAlgorithm.HMAC_SHA256, KeyExchangeAlgorithm.DHE_DSS));
			_list.Add (CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
				new CipherSuiteInfo (BulkCipherAlgorithm.AES, CipherType.Block, 16, 16, 16, 16, MACAlgorithm.HMAC_SHA1, KeyExchangeAlgorithm.DHE_DSS));
		}

		internal static bool IsSupported (CipherSuite suite)
		{
			return _list.ContainsKey (suite);
		}

		internal static CipherSuiteInfo GetSuiteInfo (CipherSuite suite)
		{
			return _list[suite];
		}
	}
}
