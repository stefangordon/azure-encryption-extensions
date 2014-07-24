using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AzureEncryptionExtensions;
using AzureEncryptionExtensions.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AzureBlobEncryptionTests
{
    [TestClass]
    public class SymmetricBlobCryptoProviderTests
    {
        // Tests expect at least 8 bytes
        readonly int sampleStreamSize = 512;

        MemoryStream streamSample;

        [TestInitialize]
        public void Initialize()
        {
            // Prepare random memory streams
            Random random = new Random();

            byte[] bufferFirst = new byte[sampleStreamSize];

            random.NextBytes(bufferFirst);

            streamSample = new MemoryStream(bufferFirst);
        }

        [TestMethod]
        public void EncryptAndDecryptStreamTest()
        {
            // Make a key
            byte[] key;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                key = aes.Key;

            // Make a provider
            IBlobCryptoProvider symmetricProvider = new SymmetricBlobCryptoProvider(key);

            // In all cases we are READING from streams 
            // (read from original, read from encrypted, read from decrypted).
            var encryptedStream = symmetricProvider.EncryptedStream(streamSample);
            var decryptedStream = symmetricProvider.DecryptedStream(encryptedStream);

            byte[] result = new byte[sampleStreamSize];
            decryptedStream.Read(result, 0, result.Length);

            Assert.IsTrue(
                result.SequenceEqual(streamSample.ToArray()),
                "Decrypted data does not match original data");
        }

        [TestMethod]
        public void IsActuallyEncryptedTest()
        {
            // Make a key
            byte[] key;
            int ivLength;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                key = aes.Key;
                ivLength = aes.BlockSize / 8;
            }

            // Make a provider
            IBlobCryptoProvider symmetricProvider = new SymmetricBlobCryptoProvider(key);

            var encryptedStream = symmetricProvider.EncryptedStream(streamSample);
            
            byte[] result = new byte[sampleStreamSize + ivLength];
            encryptedStream.Read(result, 0, result.Length);

            Assert.IsFalse(
                result.SequenceEqual(streamSample.ToArray()),
                "Encrypted stream is not encrypted");

            Assert.IsFalse(
                result.Take(5).SequenceEqual(streamSample.ToArray().Take(5)),
                "Encrypted stream is not encrypted");
        }

        [TestMethod]
        public void ToKeyFileStringAndBackTest()
        {
            IBlobCryptoProvider symmetricProvider = new SymmetricBlobCryptoProvider();
            
            string keyString = symmetricProvider.ToKeyFileString();

            IBlobCryptoProvider clonedProvider = ProviderFactory.CreateProviderFromKeyFileString(keyString);

            var encryptedStream = symmetricProvider.EncryptedStream(streamSample);
            var decryptedStream = clonedProvider.DecryptedStream(encryptedStream);

            byte[] result = new byte[sampleStreamSize];
            decryptedStream.Read(result, 0, result.Length);

            Assert.IsTrue(
                result.SequenceEqual(streamSample.ToArray()),
                "Decrypted data does not match original data");            
        }

        [TestMethod]
        public void ToKeyFileAndBackTest()
        {
            IBlobCryptoProvider symmetricProvider = new SymmetricBlobCryptoProvider();

            symmetricProvider.WriteKeyFile("keyfile.txt");

            IBlobCryptoProvider clonedProvider = ProviderFactory.CreateProviderFromKeyFile("keyfile.txt");

            var encryptedStream = symmetricProvider.EncryptedStream(streamSample);
            var decryptedStream = clonedProvider.DecryptedStream(encryptedStream);

            byte[] result = new byte[sampleStreamSize];
            decryptedStream.Read(result, 0, result.Length);

            Assert.IsTrue(
                result.SequenceEqual(streamSample.ToArray()),
                "Decrypted data does not match original data");
        }
    }
}
