
namespace AzureEncryptionExtensions.Crypto
{
    internal interface ICspProxyFactory
    {
        ICspProxy GetProvider();
    }
}
