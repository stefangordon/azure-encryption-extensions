using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using AzureEncryptionExtensions;
using AzureEncryptionExtensions.Providers;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;

namespace AzureEncryptionSample
{
    public static class Samples
    {
        public static CloudBlobContainer GetAzureContainer()
        {
            // This example references development storage, but you can 
            // replace the storage account with any real storage account as needed.
            // e.g.
            // CloudStorageAccount storageAccount = CloudStorageAccount.Parse(
            //    ConfigurationManager.ConnectionStrings["StorageConnectionString"].ConnectionString);

            CloudStorageAccount storageAccount = CloudStorageAccount.DevelopmentStorageAccount;
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
            CloudBlobContainer container = blobClient.GetContainerReference("samplecontainer");

            container.CreateIfNotExists();

            return container;
        }
        public static void UploadEncryptedFileSymmetric(string path, CloudBlobContainer container)
        {
            // Create a blob named after the file we are uploading
            CloudBlockBlob blob = container.GetBlockBlobReference("SymmetricUploadTest.jpg");

            // Create an Azure Encryption Extensions symmetric encryption provider
            // We are not passing any key material so a 256-bit AES key will be generated for us.
            var provider = new SymmetricBlobCryptoProvider();

            // Since we let the library generate a new key for us, we need to persist it somewhere
            // so we can decrypt our blob later.  We can use a simple JSON storage format built into
            // the library to store our key on disk.  
            // Remember: If we lose this key we can never retrieve our blob.
            provider.WriteKeyFile("symmetricKey.dat");

            // Encrypt and upload the file to Azure, passing in our provider
            // The file will be prepended with a random IV and encrypted with AES256.
            // This 'Encrypted' extension method mirrors the native methods but takes a provider.
            blob.UploadFromFileEncrypted(provider, path, FileMode.Open);
        }


        public static void DownloadEncryptedFileSymmetric(string destinationPath, CloudBlobContainer container)
        {
            // Since we have our AES key exported we can use the provider factory to quickly
            // insantiate a provider for working with the key again
            var provider = ProviderFactory.CreateProviderFromKeyFile("symmetricKey.dat");

            // Get a reference to our Blob again
            CloudBlockBlob blob = container.GetBlockBlobReference("SymmetricUploadTest.jpg");

            // Using our 'Encrypted' extension method to download an encrypted file
            // It will be decrypted during download and written to disk ready to use.
            blob.DownloadToFileEncrypted(provider, destinationPath, FileMode.Create);

            // You could instead download without our library, to see how it was stored encrypted in the cloud
            // blob.DownloadToFile(destinationPath, FileMode.Create);

            // Tidy up, delete our blob
            blob.DeleteIfExists();
        }

        public static void UploadEncryptedFileAsymmetric(string path, X509Certificate2 certificate, CloudBlobContainer container)
        {
            // Create a blob named after the file we are uploading
            CloudBlockBlob blob = container.GetBlockBlobReference("AsymmetricUploadTest.jpg");

            // Create an Azure Encryption Extensions asymmetric encryption provider
            // from the certificate.
            // We only need the public key in this case.
            // -----
            // If we wanted to we could also let the library generate key material for us
            // by using the empty constructor.  
            var provider = new AsymmetricBlobCryptoProvider(certificate);

            // We also have to option to persist key material to a json file
            // with or without the private key if we don't want to keep using the certificate.
            // provider.WriteKeyFile(path, [bool publicOnly]);

            // Encrypt and upload the file to Azure, passing in our provider            
            blob.UploadFromFileEncrypted(provider, path, FileMode.Open);
        }

        public static void DownloadEncryptedFileAsymmetric(string destinationPath, X509Certificate2 certificate, CloudBlobContainer container)
        {
            // We will need the private key loaded to decrypt
            // If our certificate only has the public key we'll get an exception.
            var provider = new AsymmetricBlobCryptoProvider(certificate);

            // Get a reference to our Blob again
            CloudBlockBlob blob = container.GetBlockBlobReference("AsymmetricUploadTest.jpg");

            // Using our 'Encrypted' extension method to download an encrypted file
            // It will be decrypted during download and written to disk ready to use.
            blob.DownloadToFileEncrypted(provider, destinationPath, FileMode.Create);

            // You could instead download without our library, to see how it was stored encrypted in the cloud
            // blob.DownloadToFile(destinationPath, FileMode.Create);

            // Tidy up, delete our blob
            blob.DeleteIfExists();
        }
    }
}
