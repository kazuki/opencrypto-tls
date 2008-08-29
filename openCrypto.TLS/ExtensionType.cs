namespace openCrypto.TLS
{
	enum ExtensionType : ushort
	{
		// RFC 3546 TLS Extentions 2.3
		ServerName = 0,
		MaxFragmentLength = 1,
		ClientCertificateUrl = 2,
		TrustedCaKeys = 3,
		TruncatedHmac = 4,
		StatusRequest = 5,

		// RFC 4492 ECC Cipher Suites for TLS 5.1
		EllipticCurves = 10,
		EcPointFormats = 11,
	}
}
