
#region

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using AzureEncryptionExtensions.Crypto;

#endregion

namespace AzureEncryptionExtensions.Providers
{
    public sealed class AsymmetricBlobCryptoProvider : IBlobCryptoProvider
    {
        private static readonly int DefaultKeySize = 4096;
        private ICspProxyFactory CspFactory;

        public byte[] CspBlob 
        { 
            get 
            {
                using (ICspProxy csp = CspFactory.GetProvider())
                {
                    return csp.KeyBlob;
                }
            }

            set
            {
                InitializeFromKeyBytes(value);
            }
        }

        public int AsymmetricKeySize
        {
            get
            {
                using (ICspProxy csp = CspFactory.GetProvider())
                {
                    return csp.AsymmetricKeySize;
                }
            }
        }

        public AsymmetricBlobCryptoProvider()
            : this(CspProxyFactory.Create(DefaultKeySize))
        {
        }

        public void InitializeFromKeyBytes(byte[] cspBlob)
        {
            CspFactory = CspProxyFactory.Create(cspBlob);
        }

        private AsymmetricBlobCryptoProvider(ICspProxyFactory factory)
        {
            CspFactory = factory;
        }

        public AsymmetricBlobCryptoProvider(byte[] cspBlob)
            : this(CspProxyFactory.Create(cspBlob))
        {
        }

        public AsymmetricBlobCryptoProvider(X509Certificate2 certificate, bool loadPrivateKeyIfAvailable = true)
            : this(CspProxyFactory.Create(certificate, loadPrivateKeyIfAvailable))
        {
        }

        public void WriteKeyFile(string path)
        {
            WriteKeyFile(path, false);
        }

        public void WriteKeyFile(string path, bool publicOnly)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentNullException("path", "Must provide valid file path.");

            File.WriteAllText(path, ToKeyFileString(publicOnly));
        }

        public string ToKeyFileString()
        {
            return ToKeyFileString(false);
        }

        public string ToKeyFileString(bool publicOnly)
        {
            KeyFileStorage keyStorage;
            byte[] temporaryCspBlob;

            using (ICspProxy csp = CspFactory.GetProvider())
            {
                if (publicOnly)
                {
                    temporaryCspBlob = csp.PublicKeyBlob;
                }
                else
                {
                    temporaryCspBlob = csp.KeyBlob;
                }
                
                keyStorage = new KeyFileStorage
                {
                    KeyMaterial = temporaryCspBlob,
                    ProviderType = GetType().ToString(),
                    ContainsPrivateKey = !publicOnly && !csp.IsPublicOnly
                };
            }

            /*
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(CspBlob);

                if (publicOnly && !rsa.PublicOnly)
                {
                    temporaryCspBlob = rsa.ExportCspBlob(false);
                }
                else
                {
                    temporaryCspBlob = CspBlob;
                }

                keyStorage = new KeyFileStorage
                {
                    KeyMaterial = temporaryCspBlob,
                    ProviderType = GetType().ToString(),
                    ContainsPrivateKey = !publicOnly && !rsa.PublicOnly
                };
            }
            */

            return JsonConvert.SerializeObject(keyStorage);
        }


        public Stream EncryptedStream(Stream streamToEncrypt)
        {
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            using (ICspProxy csp = CspFactory.GetProvider())
            {
                // Set new key but retain randomized IV created during provider instantiation.
                aesAlg.Key = GenerateRandomKey();
                byte[] encryptedKey = csp.Encrypt(aesAlg.Key);

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor();

                MemoryStream keyStream = new MemoryStream(encryptedKey);
                MemoryStream ivStream = new MemoryStream(aesAlg.IV);
                CryptoStream cryptoStream = new CryptoStream(streamToEncrypt, encryptor, CryptoStreamMode.Read);

                return new ConcatenatedStream(keyStream, ivStream, cryptoStream);
            }
        }

        public Stream DecryptedStream(Stream streamToDecrypt)
        {            
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            using (ICspProxy csp = CspFactory.GetProvider())
            {
                // Get the AES key from the stream
                // The length will be the size of the RSA key which was used to encrypt
                // the 256 bit AES key (assuming the RSA key is always larger than 256 bit).
                byte[] encryptedKey = new byte[AsymmetricKeySize / 8];
                byte[] decryptedKey;
                streamToDecrypt.Read(encryptedKey, 0, encryptedKey.Length);
                decryptedKey = csp.Decrypt(encryptedKey);

                // Attempt to read IV from Stream
                byte[] ivBytes = new byte[aesAlg.BlockSize / 8];
                streamToDecrypt.Read(ivBytes, 0, ivBytes.Length);

                // Set key and initialization vector
                aesAlg.Key = decryptedKey;
                aesAlg.IV = ivBytes;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor();

                CryptoStream cryptoStream = new CryptoStream(streamToDecrypt, decryptor, CryptoStreamMode.Read);

                return cryptoStream;
            }
        }

        private static byte[] GenerateRandomKey()
        {
            // AES 256 key
            byte[] key = new byte[256 / 8];

            // Cryptographically strong random bytes
            RNGCryptoServiceProvider rngProvider = new RNGCryptoServiceProvider();
            rngProvider.GetNonZeroBytes(key);

            return key;
        }

        /*
        private static byte[] EncryptKey(ICspProxy csp, byte[] key)
        {

            byte[] encryptedKey;

            // Encrypt using RSA provider
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(cspBlob);
                encryptedKey = rsa.Encrypt(key, false);
            }

            return encryptedKey;
        }

        private static byte[] DecryptKey(byte[] cspBlob, byte[] encryptedKey)
        {
            byte[] decryptedKey;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(cspBlob);

                if (rsa.PublicOnly)
                {
                    throw new CryptographicProviderException(
                        "Unable to decrypt data because the private key is not available. " +
                        "Please instantiate an AsymmetricBlobCryptoProvider with a valid private key.");
                }

                decryptedKey = rsa.Decrypt(encryptedKey, false);
            }

            return decryptedKey;
        }
         */
    }
}
