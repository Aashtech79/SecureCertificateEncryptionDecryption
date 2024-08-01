using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Newtonsoft.Json;

namespace SecureCertificateEncryptionDecryption
{
	class Program
	{
		static void Main(string[] args)
		{
			string thumbprint = "7e2364041558b69360f64ea962d51ddeb6375d1c"; // Replace with your certificate thumbprint
			string originalString = "Hello, World!";

			try
			{
				// Find certificate by thumbprint
				X509Certificate2 certificate = X509Certificate2Helper.GetCertificateByThumbprint(thumbprint);
				if (certificate == null)
				{
					throw new Exception("Certificate not found");
				}

				// Encrypt the string
				string encryptedString = Encrypt.EncryptString(originalString, certificate, thumbprint);
				Console.WriteLine($"Encrypted String: {encryptedString}");

				// Decrypt the string
				string decryptedString = Decrypt.DecryptString(encryptedString);
				Console.WriteLine($"Decrypted String: {decryptedString}");
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Error: {ex.Message}");
			}
		}

	

	}
}
