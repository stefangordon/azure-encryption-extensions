using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AzureEncryptionExtensions.Providers;

namespace AzureEncryptionExtensions
{
    public class CryptographicProviderException : Exception
    {
        public CryptographicProviderException(string message)
            : base(message)
        {
   
        }
    }

    public class InvalidEncryptedStreamException : Exception
    {
        public InvalidEncryptedStreamException(string message)
            : base(message)
        {

        }
    }

    public class InvalidKeyFileException : Exception
    {
        public InvalidKeyFileException(string message)
            : base(message)
        {

        }
    }
}
