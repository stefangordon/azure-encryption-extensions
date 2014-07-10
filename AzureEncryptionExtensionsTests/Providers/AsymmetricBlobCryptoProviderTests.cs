using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using AzureBlobEncryption;
using AzureBlobEncryption.Providers;
using AzureEncryptionExtensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AzureBlobEncryptionTests
{
    [TestClass]
    public class AsymmetricBlobCryptoProviderTests
    {
        byte[] testCspBlob;

        // Tests expect at least 8 bytes
        readonly int sampleStreamSize = 512;
        MemoryStream streamSample;

        [TestInitialize]
        public void Initialize()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(4096))
                testCspBlob = rsa.ExportCspBlob(true);

            // Prepare random memory streams
            Random random = new Random();

            byte[] bufferFirst = new byte[sampleStreamSize];

            random.NextBytes(bufferFirst);

            streamSample = new MemoryStream(bufferFirst);
        }

        [TestMethod]
        public void KeyGenerationTest()
        {
            PrivateType pt = new PrivateType(typeof(AsymmetricBlobCryptoProvider));

            byte[] key = (byte[])pt.InvokeStatic("GenerateRandomKey");
            byte[] encryptedKey = (byte[])pt.InvokeStatic("EncryptKey", new Object[] { testCspBlob, key });
            
            // The two keys shouldn't be the same...
            Assert.IsFalse(key.SequenceEqual(encryptedKey));

            // And we expect it to grow to the same size as the RSA Key
            Assert.IsTrue(encryptedKey.Length == 4096 / 8);

            // Now lets try to decrypt a key
            byte[] decryptedKey = (byte[])pt.InvokeStatic("DecryptKey", new Object[] { testCspBlob, encryptedKey });

            // Sanity check, it should be 256 bit / 32 bytes and not contain any zeros.
            Assert.IsTrue(decryptedKey.Length == 256/8, "Key length is incorrect");
            Assert.IsTrue(decryptedKey[0] != 0, "Key starts with an empty byte");

            // And of course, the round tripped key should match original
            Assert.IsTrue(key.SequenceEqual(decryptedKey));
        }

        [TestMethod]
        public void EncryptAndDecryptStreamTest()
        {
            // Make a provider
            IBlobCryptoProvider asymmetricProvider = new AsymmetricBlobCryptoProvider();

            // In all cases we are READING from streams 
            // (read from original, read from encrypted, read from decrypted).
            var encryptedStream = asymmetricProvider.EncryptedStream(streamSample);
            var decryptedStream = asymmetricProvider.DecryptedStream(encryptedStream);

            byte[] result = new byte[sampleStreamSize];
            decryptedStream.Read(result, 0, result.Length);

            Assert.IsTrue(
                result.SequenceEqual(streamSample.ToArray()),
                "Decrypted data does not match original data");
        }

        [TestMethod]
        [DeploymentItem("TestCertificates")]
        public void EncryptAndDecryptStreamWith1024BitX509Test()
        {
            // Load Certificate
            X509Certificate2 cert = new X509Certificate2("1024.pfx", string.Empty, X509KeyStorageFlags.Exportable);

            EncryptAndDecryptStreamWithX509(cert);
        }

        [TestMethod]
        [DeploymentItem("TestCertificates")]
        public void EncryptAndDecryptStreamWith2048BitX509Test()
        {
            // Load Certificate
            X509Certificate2 cert = new X509Certificate2("2048.pfx", string.Empty, X509KeyStorageFlags.Exportable);

            EncryptAndDecryptStreamWithX509(cert);
        }

        [TestMethod]
        [DeploymentItem("TestCertificates")]
        public void EncryptAndDecryptStreamWith4096BitX509Test()
        {
            // Load Certificate
            X509Certificate2 cert = new X509Certificate2("4096.pfx", string.Empty, X509KeyStorageFlags.Exportable);

            EncryptAndDecryptStreamWithX509(cert);
        }

        [TestMethod]
        [DeploymentItem("TestCertificates")]
        [ExpectedException(typeof(CryptographicProviderException))]
        public void DecryptFailsWithX509IfPrivateKeyNotLoadedTest()
        {
            // Load Certificate
            X509Certificate2 cert = new X509Certificate2("4096.pfx", string.Empty, X509KeyStorageFlags.Exportable);

            // Make a provider
            IBlobCryptoProvider asymmetricProvider = new AsymmetricBlobCryptoProvider(cert, false);

            // In all cases we are READING from streams 
            // (read from original, read from encrypted, read from decrypted).
            var encryptedStream = asymmetricProvider.EncryptedStream(streamSample);
            var decryptedStream = asymmetricProvider.DecryptedStream(encryptedStream);

            byte[] result = new byte[sampleStreamSize];
            decryptedStream.Read(result, 0, result.Length);

            Assert.IsTrue(
                result.SequenceEqual(streamSample.ToArray()),
                "Decrypted data does not match original data");
        }     

        [TestMethod]
        public void IsActuallyEncryptedTest()
        {
            // Make a provider
            IBlobCryptoProvider asymmetricProvider = new AsymmetricBlobCryptoProvider();

            var encryptedStream = asymmetricProvider.EncryptedStream(streamSample);

            byte[] result = new byte[sampleStreamSize + (4096+256)/8];
            encryptedStream.Read(result, 0, result.Length);

            Assert.IsFalse(
                result.SequenceEqual(streamSample.ToArray()),
                "Encrypted stream is not encrypted");

            Assert.IsFalse(
                result.Take(5).SequenceEqual(streamSample.ToArray().Take(5)),
                "Encrypted stream is not encrypted");
        }

        private void EncryptAndDecryptStreamWithX509(X509Certificate2 certificate)
        {
            // Make a provider
            IBlobCryptoProvider asymmetricProvider = new AsymmetricBlobCryptoProvider(certificate);

            // In all cases we are READING from streams 
            // (read from original, read from encrypted, read from decrypted).
            var encryptedStream = asymmetricProvider.EncryptedStream(streamSample);
            var decryptedStream = asymmetricProvider.DecryptedStream(encryptedStream);

            byte[] result = new byte[sampleStreamSize];
            decryptedStream.Read(result, 0, result.Length);

            Assert.IsTrue(
                result.SequenceEqual(streamSample.ToArray()),
                "Decrypted data does not match original data");
        }

    }
}
