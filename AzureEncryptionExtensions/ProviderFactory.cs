// /*
//  Copyright (c) Stefan Gordon
//  All Rights Reserved
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
//  License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// 
//  THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED,
//  INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
//  MERCHANTABLITY OR NON-INFRINGEMENT.
// 
//  See the Apache 2 License for the specific language governing permissions and limitations under the License.
//  */

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
