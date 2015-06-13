
namespace AzureEncryptionExtensions
{
    public class KeyFileStorage
    {
        public string ProviderType { get; set; }
        public bool ContainsPrivateKey { get; set; }
        public byte[] KeyMaterial { get; set; }        
    }
}
