using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AzureEncryptionExtensions.Crypto
{
    internal interface ICspProxy : IDisposable
    {
        byte[] KeyBlob { get; }
        byte[] PublicKeyBlob { get; }
        bool IsPublicOnly { get; }
        int AsymmetricKeySize { get; }

        byte[] Encrypt(byte[] value);
        byte[] Decrypt(byte[] encrypted);
    }
}
