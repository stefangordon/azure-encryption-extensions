﻿using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Blob;
using AzureBlobEncryption;
using AzureBlobEncryption.Providers;
using System.Security.Cryptography;
using System.Text;

namespace AzureBlobEncryptionTests
{
    [TestClass]
    public class FunctionalTests
    {

        [TestMethod]
        public void BlockBlob_UploadDownload_File()
        {

            using (var file = new TemporaryFile(512))
            {
                CloudStorageAccount storageAccount = CloudStorageAccount.DevelopmentStorageAccount;
                CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();

                CloudBlobContainer container = blobClient.GetContainerReference("testcontainer");

                container.CreateIfNotExists();

                CloudBlockBlob blob = container.GetBlockBlobReference(file.fileInfo.Name);

                // Create provider
                var provider = new SymmetricBlobCryptoProvider();

                // Upload file
                blob.UploadFromFileEncrypted(provider, file.fileInfo.FullName, FileMode.Open);

                // Download file
                string destinationFile = file.fileInfo.FullName + "decrypted";
                blob.DownloadToFileEncrypted(provider, destinationFile, FileMode.Create);

                // Compare raw and decrypted files
                Assert.AreEqual(GetFileHash(file.fileInfo.FullName), GetFileHash(destinationFile));

                // Download file again, without our library, to ensure it was actually encrypted
                string encryptedDestinationFile = file.fileInfo.FullName + "encrypted";
                blob.DownloadToFile(encryptedDestinationFile, FileMode.Create);

                // Delete blob
                blob.DeleteIfExists();

                // Compare raw and encrypted files
                Assert.AreNotEqual(GetFileHash(file.fileInfo.FullName), GetFileHash(encryptedDestinationFile));

                // Cleanup
                if (File.Exists(destinationFile))
                {
                    File.Delete(destinationFile);
                }

                if (File.Exists(encryptedDestinationFile))
                {
                    File.Delete(encryptedDestinationFile);
                }
            }

        }

        public string GetFileHash(string filename)
        {
            var hash = new SHA1Managed();
            var clearBytes = File.ReadAllBytes(filename);
            var hashedBytes = hash.ComputeHash(clearBytes);
            return ConvertBytesToHex(hashedBytes);
        }

        public string ConvertBytesToHex(byte[] bytes)
        {
            var sb = new StringBuilder();

            for (var i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString("x"));
            }
            return sb.ToString();
        }

    }
}