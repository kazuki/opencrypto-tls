using System;
using System.Collections.Generic;
using System.Text;

namespace openCrypto.TLS
{
	public class CipherSuiteSelector
	{
		static CipherSuiteSelector _defaultInstance = null;

		protected CipherSuiteSelector ()
		{
		}

		public static CipherSuiteSelector DefaultInstance {
			get {
				if (_defaultInstance == null)
					_defaultInstance = new CipherSuiteSelector ();
				return _defaultInstance;
			}
		}

		public virtual CipherSuite Select (CipherSuite[] suites)
		{
			CipherSuite[] supports = SupportedCipherSuites.SupportedSuites;
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
