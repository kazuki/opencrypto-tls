using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using openCrypto.EllipticCurve.Signature;
using System.Security.Cryptography.X509Certificates;

namespace openCrypto.TLS
{
	public class AppLoader
	{
		static void Main ()
		{
			X509Certificate cert = new X509Certificate ("localhost.x509");
			X509Certificate[] certs = new X509Certificate[] {cert};
			ECDSA ecdsa = new ECDSA (openCrypto.EllipticCurve.ECDomainNames.secp256r1);
			ecdsa.Parameters.PrivateKey = new byte[] {0x31, 0xfe, 0xa8, 0xf8, 0xdb, 0x32, 0x57, 0x79, 0xb2, 0xaf, 0xb6, 0x34, 0xef, 0xe6, 0x60,
				0x00, 0x75, 0xa5, 0xd3, 0xa6, 0xba, 0x7a, 0x07, 0xc1, 0x5b, 0x8f, 0x81, 0xe1, 0xce, 0x48,
				0xb2, 0x9a};

			Socket server = new Socket (AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
			server.Bind (new IPEndPoint (IPAddress.Any, 443));
			server.Listen (8);

			while (true) {
				Socket client;
				try {
					client = server.Accept ();
					using (NetworkStream nstrm = new NetworkStream (client, FileAccess.ReadWrite, true))
					using (TLSServerStream strm = new TLSServerStream (nstrm, true, certs, ecdsa)) {
						byte[] raw = new byte[256];
						strm.Read (raw, 0, raw.Length);
						Console.WriteLine (System.Text.Encoding.ASCII.GetString (raw));
						raw = System.Text.Encoding.UTF8.GetBytes ("HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n" +
							"<html><body><h1>Hello ECC World !</h1><p>楕円曲線暗号の世界へようこそ！</p>" +
							"<p>このメッセージはECDSA(secp256r1)によってサーバを検証後、<br />" +
							"ECDH(secp256r1)によって共有した鍵を利用して、<br />" +
							"AES 256bitで暗号化されています</p></body></html>\r\n");
						strm.Write (raw, 0, raw.Length);
					}
				} catch (IOException) {
				} catch {}
			}
		}
	}
}
