namespace openCrypto.TLS
{
	enum ContentType : byte
	{
		ChangeCipherSpec = 20,
		Alert = 21,
		Handshake = 22,
		ApplicationData = 23,
		SSL20Compatible = 0x80
	}
}
