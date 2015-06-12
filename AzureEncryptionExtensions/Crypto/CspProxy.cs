using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AzureEncryptionExtensions.Crypto
{
    internal abstract class CspProxy : ICspProxy
    {
        protected readonly RSACryptoServiceProvider Rsa;

        public byte[] KeyBlob
        {
            get 
            {
                if (IsPublicOnly) return PublicKeyBlob;
                if (!IsExportable) throw new InvalidOperationException("Key cannot be exported.");
                return Rsa.ExportCspBlob(true);
            }
        }

        public byte[] PublicKeyBlob
        {
            get 
            {
                return Rsa.ExportCspBlob(false);
            }
        }

        public bool IsPublicOnly
        {
            get { return Rsa.PublicOnly; }
        }

        public bool IsExportable
        {
            get 
            {
                // If the key container is not accessible, then this provider was generated
                // dynamically and should always have the key available
                return Rsa.CspKeyContainerInfo.Accessible ?
                    Rsa.CspKeyContainerInfo.Exportable :
                    true;
            }
        }

        public int AsymmetricKeySize
        {
            get;
            private set;
        }

        public CspProxy(RSACryptoServiceProvider rsa, int keySize)
        {
            Rsa = rsa;
            AsymmetricKeySize = keySize;
        }

        public byte[] Encrypt(byte[] value)
        {
            return Rsa.Encrypt(value, false);
        }

        public byte[] Decrypt(byte[] encrypted)
        {
            if (IsPublicOnly)
            {
                throw new CryptographicProviderException(
                        "Unable to decrypt data because the private key is not available. " +
                        "Please instantiate an AsymmetricBlobCryptoProvider with a valid private key.");
            }

            return Rsa.Decrypt(encrypted, false);
        }

        public abstract void Dispose();
    }
}
