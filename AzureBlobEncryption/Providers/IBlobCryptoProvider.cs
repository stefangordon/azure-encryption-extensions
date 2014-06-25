using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AzureBlobEncryption.Providers
{
    public interface IBlobCryptoProvider
    {
        Stream EncryptedStream(Stream streamToEncrypt);

        Stream DecryptedStream(Stream streamToDecrypt);

        void WriteKeyFile(String path);
        String ToKeyFileString();
    }
}
