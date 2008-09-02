using System;

namespace openCrypto.TLS.KeyExchange
{
	interface IKeyExchange
	{
		/// <summary>
		/// ServerKeyExchange.Paramsを作成して、引数に指定されたバッファにコピーする
		/// </summary>
		/// <returns>コピーしたバイト数</returns>
		int CreateServerKeyExchangeParams (byte[] params_buffer, int offset);

		/// <summary>
		/// ServerKeyExchangeの署名を指定された引数の情報より生成して、バッファにコピーする
		/// </summary>
		/// <returns>署名のバイト数</returns>
		int CreateServerKeyExchangeSign (SecurityParameters sparams, byte[] params_buffer, int params_offset, int params_length, byte[] sign_buffer, int sign_offset);

		/// <summary>
		/// ClientKeyExchangeよりサーバ側のMasterSecretを求め、SecurityParametersに設定します
		/// </summary>
		void ComputeServerMasterSecret (SecurityParameters sparams, byte[] raw, int offset, int length);
	}
}
