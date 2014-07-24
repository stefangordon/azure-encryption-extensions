using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace AzureEncryptionExtensions
{
    public class KeyFileStorage
    {
        public string ProviderType { get; set; }
        public bool ContainsPrivateKey { get; set; }
        public byte[] KeyMaterial { get; set; }        
    }
}
