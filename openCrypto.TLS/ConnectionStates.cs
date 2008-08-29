using System;

namespace openCrypto.TLS
{
	class ConnectionStates
	{
		SecurityParameters _sparams = new SecurityParameters ();

		public ConnectionStates ()
		{
		}

		#region Properties
		public SecurityParameters SecurityParameters {
			get { return _sparams; }
		}
		#endregion
	}
}
