using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AzureBlobEncryption.Providers;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;

namespace AzureBlobEncryption
{
    public static class BlobExtensions
    {
        public static void UploadFromFileEncrypted(this ICloudBlob blob, IBlobCryptoProvider provider, string path, FileMode mode, 
            AccessCondition accessCondition = null, BlobRequestOptions options = null, 
            OperationContext operationContext = null)        
        {
            using (FileStream fileStream = new FileStream(path, mode))
            using (Stream encryptedStream = provider.EncryptedStream(fileStream))
            {
                blob.UploadFromStream(encryptedStream, accessCondition, options, operationContext);
            }     
        }

        public static void UploadFromStreamEncrypted(this ICloudBlob blob, IBlobCryptoProvider provider, Stream stream,
            AccessCondition accessCondition = null, BlobRequestOptions options = null,
            OperationContext operationContext = null)
        {
            using (Stream encryptedStream = provider.EncryptedStream(stream))
            {
                blob.UploadFromStream(encryptedStream, accessCondition, options, operationContext);
            }
        }

        public static void DownloadToFileEncrypted(this ICloudBlob blob, IBlobCryptoProvider provider, string path, FileMode mode,
            AccessCondition accessCondition = null, BlobRequestOptions options = null,
            OperationContext operationContext = null)
        {
            using (FileStream fileStream = new FileStream(path, mode))
            {
                blob.DownloadToStreamEncrypted(provider, fileStream, accessCondition, options, operationContext);
            }
        }

        public static void DownloadToStreamEncrypted(this ICloudBlob blob, IBlobCryptoProvider provider, Stream stream, 
            AccessCondition accessCondition = null, BlobRequestOptions options = null,
            OperationContext operationContext = null)
        {
            using (Stream blobStream = blob.OpenRead(accessCondition, options, operationContext))
            using (Stream decryptedStream = provider.DecryptedStream(blobStream))
            {
                decryptedStream.CopyTo(stream);
            }
        }
    }
}
