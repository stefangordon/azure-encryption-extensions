using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

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
