using System;
using System.Security.Cryptography.X509Certificates;

namespace openCrypto.TLS
{
	public class CipherSuiteSelector
	{
		CipherSuite[] _supports;

		public CipherSuiteSelector (X509Certificate cert)
		{
			KeyExchangeAlgorithm[] keyExchanges;
			string algo_oid = cert.GetKeyAlgorithm ();
			if (algo_oid == "1.2.840.10045.2.1") {
				keyExchanges = new KeyExchangeAlgorithm[] {
					KeyExchangeAlgorithm.DH_anon,
					KeyExchangeAlgorithm.ECDH_anon,
					KeyExchangeAlgorithm.ECDH_ECDSA,
					KeyExchangeAlgorithm.ECDHE_ECDSA
				};
			} else if (algo_oid == "1.2.840.10040.4.1") {
				keyExchanges = new KeyExchangeAlgorithm[] {
					KeyExchangeAlgorithm.DH_anon,
					KeyExchangeAlgorithm.DH_DSS,
					KeyExchangeAlgorithm.DHE_DSS,
					KeyExchangeAlgorithm.ECDH_anon
				};
			} else if (algo_oid == "1.2.840.113549.1.1.1") {
				keyExchanges = new KeyExchangeAlgorithm[] {
					KeyExchangeAlgorithm.DH_anon,
					KeyExchangeAlgorithm.DH_RSA,
					KeyExchangeAlgorithm.DHE_RSA,
					KeyExchangeAlgorithm.ECDH_anon,
					KeyExchangeAlgorithm.ECDH_RSA,
					KeyExchangeAlgorithm.ECDHE_RSA,
					KeyExchangeAlgorithm.RSA
				};
			} else {
				throw new NotSupportedException ();
			}

			_supports = SupportedCipherSuites.FilterKeyExchange (keyExchanges);
		}

		public virtual CipherSuite Select (CipherSuite[] suites)
		{
			CipherSuite[] supports = _supports;
			int minIdx = int.MaxValue;
			for (int q = 0; q < suites.Length; q ++) {
				for (int i = 0; i < supports.Length; i++) {
					if (suites[q] == supports[i]) {
						if (minIdx > i)
							minIdx = i;
						break;
					}
				}
			}
			if (minIdx == int.MaxValue)
				return CipherSuite.NONE;
			return supports[minIdx];
		}
	}
}
