using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureCertificateEncryptionDecryption
{
	public class Decrypt
	{
		public static string DecryptString(string encryptedText)
		{
			var payload = JsonConvert.DeserializeObject<dynamic>(Encoding.UTF8.GetString(Convert.FromBase64String(encryptedText)));
			string thumbprint = payload.Thumbprint;
			byte[] nonce = Convert.FromBase64String(payload.Nonce.ToString());
			byte[] encryptedAesKey = Convert.FromBase64String(payload.EncryptedAesKey.ToString());
			byte[] encryptedData = Convert.FromBase64String(payload.EncryptedData.ToString());
			byte[] iv = Convert.FromBase64String(payload.Iv.ToString());

			// Find the certificate using the thumbprint
			X509Certificate2 certificate =X509Certificate2Helper.GetCertificateByThumbprint(thumbprint);
			if (certificate == null)
			{
				throw new Exception("Certificate not found");
			}

			using (RSA rsa = certificate.GetRSAPrivateKey())
			{
				byte[] aesKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);

				using (Aes aes = Aes.Create())
				{
					aes.KeySize = 256;
					aes.BlockSize = 128;
					aes.Key = aesKey;
					aes.IV = iv;

					ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
					byte[] decryptedData;

					using (var ms = new System.IO.MemoryStream(encryptedData))
					{
						using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
						{
							using (var resultStream = new System.IO.MemoryStream())
							{
								cs.CopyTo(resultStream);
								decryptedData = resultStream.ToArray();
							}
						}
					}

					return Encoding.UTF8.GetString(decryptedData);
				}
			}
		}

	}
}
