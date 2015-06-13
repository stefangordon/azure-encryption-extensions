
#region

using System;
using System.IO;
using AzureEncryptionExtensions.Providers;
using Newtonsoft.Json;

#endregion

namespace AzureEncryptionExtensions
{
    public static class ProviderFactory
    {
        public static IBlobCryptoProvider CreateProviderFromKeyFileString(string keyFileData)
        {
            if (string.IsNullOrWhiteSpace(keyFileData))
                throw new ArgumentNullException("keyFileData", "You can not provide an empty key file!");

            KeyFileStorage keyStorage;

            try
            {
                keyStorage = JsonConvert.DeserializeObject<KeyFileStorage>(keyFileData);
            }
            catch (JsonReaderException je)
            {
                throw new InvalidKeyFileException("Could not deserialize the provided key file into valid provider metadata. \n" + je);
            }

            IBlobCryptoProvider provider = 
                (IBlobCryptoProvider)Activator.CreateInstance(Type.GetType(keyStorage.ProviderType));

            provider.InitializeFromKeyBytes(keyStorage.KeyMaterial);

            return provider;
        }

        public static IBlobCryptoProvider CreateProviderFromKeyFile(string keyFilePath)
        {
            if (!File.Exists(keyFilePath))
                throw new ArgumentException("File does not exist", "keyFilePath");

            return CreateProviderFromKeyFileString(File.ReadAllText(keyFilePath));
        }
    }
}
