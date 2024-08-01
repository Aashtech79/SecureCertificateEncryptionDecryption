using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SecureCertificateEncryptionDecryption
{
	public class X509Certificate2Helper
	{
		public static X509Certificate2 GetCertificateByThumbprint(string thumbprint)
		{
			X509Store store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);
			store.Open(OpenFlags.ReadOnly);

			foreach (X509Certificate2 cert in store.Certificates)
			{
				if (cert.Thumbprint != null && cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
				{
					return cert;
				}
			}

			return null;
		}

	}
}
