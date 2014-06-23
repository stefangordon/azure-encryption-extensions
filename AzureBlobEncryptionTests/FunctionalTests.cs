using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Blob;

namespace AzureBlobEncryptionTests
{
    [TestClass]
    public class FunctionalTests
    {

        [TestMethod]
        public void UploadBlockBlob()
        {

            using (var file = new TemporaryFile(512))
            {
                CloudStorageAccount storageAccount = CloudStorageAccount.DevelopmentStorageAccount;
                CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();

                CloudBlobContainer container = blobClient.GetContainerReference("testcontainer");

                container.CreateIfNotExists();

                CloudBlockBlob blob = container.GetBlockBlobReference(file.fileInfo.Name);

                blob.UploadFromFile(file.fileInfo.FullName, FileMode.Open);

            }

        }

    }
}
