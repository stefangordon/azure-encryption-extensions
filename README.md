Azure Encryption Extensions
===========================

Overview
---------

Azure Encryption Extensions is a simple library designed to streamline the work required to encrypt data stored in Azure Blob Storage.  Data is encrypted on-the-fly as it is uploaded to Azure, and decrypted as it is downloaded.  Unencrypted data never leaves your machine and you can manage your keys however you'd like.

Supported Algorithms
--------------------
Azure Encryption Extensions currently contains two providers, an [AsymmetricBlobCryptoProvider](#AsymmetricBlobCryptoProvider) and a [SymmetricBlobCryptoProvider](#SymmetricBlobCryptoProvider).  These provide the choice between symmetric AES encryption or asymmetric RSA encryption.  To ensure performance for large files the asymmetric provider internally encrypts data with AES256 based on a randomly generated key which is encrypted with RSA and prepended on the blob stream.  This provides the benefits of public/private key management with the speed of symmetric encryption.  

In both cases the .NET framework Cryptographic Service Providers provide the underlying implementation.

Getting Started
---------------

The library provides extensions for ICloudBlob which are identical to the existing methods, but with the addition of an encryption provider parameter.  This makes it trivial to modify existing Azure Storage code to add encryption without refactoring.

Here we encrypt a blob using an X509Certificate2 as our key:
```csharp
CloudBlockBlob blob = container.GetBlockBlobReference("TestBlob");

// Create an Asymmetric provider from an X509Certificate2
var provider = new AsymmetricBlobCryptoProvider(certificate);

// Encrypt and upload the file to Azure, passing in our provider            
blob.UploadFromFileEncrypted(provider, path, FileMode.Open);

// Download and decrypt the file
blob.DownloadToFileEncrypted(provider, destinationPath, FileMode.Create);

```


Additional samples are available in the AzureEncryptionSample project in the repository.

Providers
---------

###AsymmetricBlobCryptoProvider
TBD.

###SymmetricBlobCryptoProvider
TBD.


