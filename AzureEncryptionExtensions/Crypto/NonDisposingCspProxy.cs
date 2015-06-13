using System.Security.Cryptography;

namespace AzureEncryptionExtensions.Crypto
{
    internal class NonDisposingCspProxy : CspProxy
    {
        public NonDisposingCspProxy(RSACryptoServiceProvider rsa, int keySize)
            : base(rsa, keySize)
        {
        }

        public override void Dispose()
        {
        }
    }
}
