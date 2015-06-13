
#region

using System;
using System.IO;

#endregion

namespace AzureEncryptionExtensions.Providers
{
    public interface IBlobCryptoProvider
    {
        Stream EncryptedStream(Stream streamToEncrypt);

        Stream DecryptedStream(Stream streamToDecrypt);

        void WriteKeyFile(String path);
        String ToKeyFileString();

        void InitializeFromKeyBytes(byte[] key);
    }
}
