namespace openCrypto.TLS
{
	enum ProtocolVersion : ushort
	{
		SSL30 = (3 << 8 | 0),
		TLS10 = (3 << 8 | 1),
		TLS11 = (3 << 8 | 2),
		TLS12 = (3 << 8 | 3),
	}
}
