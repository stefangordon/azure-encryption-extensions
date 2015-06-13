using System.Security.Cryptography;

namespace AzureEncryptionExtensions.Crypto
{
    internal class DisposingCspProxy : CspProxy
    {
        public DisposingCspProxy(RSACryptoServiceProvider rsa, int keySize)
            : base(rsa, keySize)
        {
        }

        public override void Dispose()
        {
            Rsa.Dispose();
        }
    }
}
