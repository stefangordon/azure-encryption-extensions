using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

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
