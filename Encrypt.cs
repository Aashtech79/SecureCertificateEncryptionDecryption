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
	public class Encrypt
	{
		public static string EncryptString(string plainText, X509Certificate2 certificate, string thumbprint)
		{
			using (RSA rsa = certificate.GetRSAPublicKey())
			{
				byte[] dataToEncrypt = Encoding.UTF8.GetBytes(plainText);

				// Generate a unique nonce (IV) for AES
				byte[] nonce = new byte[16];
				using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
				{
					rng.GetBytes(nonce);
				}

				using (Aes aes = Aes.Create())
				{
					aes.KeySize = 256;
					aes.BlockSize = 128;
					aes.GenerateKey();
					aes.GenerateIV();

					ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
					byte[] encryptedData;

					using (var ms = new System.IO.MemoryStream())
					{
						using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
						{
							cs.Write(dataToEncrypt, 0, dataToEncrypt.Length);
						}
						encryptedData = ms.ToArray();
					}

					// Encrypt the AES key with the RSA public key
					byte[] encryptedAesKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);

					// Combine nonce, encrypted AES key, and encrypted data
					var payload = new
					{
						Thumbprint = thumbprint,
						Nonce = Convert.ToBase64String(nonce),
						EncryptedAesKey = Convert.ToBase64String(encryptedAesKey),
						EncryptedData = Convert.ToBase64String(encryptedData),
						Iv = Convert.ToBase64String(aes.IV)
					};

					return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));
				}
			}
		}
	}
}
