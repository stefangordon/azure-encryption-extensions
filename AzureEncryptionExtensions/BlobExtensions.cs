
#region

using System.IO;
using AzureEncryptionExtensions.Providers;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using System.Threading.Tasks;

#endregion

namespace AzureEncryptionExtensions
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

        public async static Task UploadFromFileEncryptedAsync(this ICloudBlob blob, IBlobCryptoProvider provider, string path, FileMode mode,
    AccessCondition accessCondition = null, BlobRequestOptions options = null,
    OperationContext operationContext = null)
        {
            using (FileStream fileStream = new FileStream(path, mode))
            using (Stream encryptedStream = provider.EncryptedStream(fileStream))
            {
                await blob.UploadFromStreamAsync(encryptedStream, accessCondition, options, operationContext);
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

        public async static Task UploadFromStreamEncryptedAsync(this ICloudBlob blob, IBlobCryptoProvider provider, Stream stream,
    AccessCondition accessCondition = null, BlobRequestOptions options = null,
    OperationContext operationContext = null)
        {
            using (Stream encryptedStream = provider.EncryptedStream(stream))
            {
                await blob.UploadFromStreamAsync(encryptedStream, accessCondition, options, operationContext);
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

        public async static Task DownloadToFileEncryptedAsync(this ICloudBlob blob, IBlobCryptoProvider provider, string path, FileMode mode,
    AccessCondition accessCondition = null, BlobRequestOptions options = null,
    OperationContext operationContext = null)
        {
            using (FileStream fileStream = new FileStream(path, mode))
            {
                await blob.DownloadToStreamEncryptedAsync(provider, fileStream, accessCondition, options, operationContext);
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

        public async static Task DownloadToStreamEncryptedAsync(this ICloudBlob blob, IBlobCryptoProvider provider, Stream stream,
        AccessCondition accessCondition = null, BlobRequestOptions options = null,
        OperationContext operationContext = null)
        {
            using (Stream blobStream = await blob.OpenReadAsync(accessCondition, options, operationContext))
            using (Stream decryptedStream = provider.DecryptedStream(blobStream))
            {
                await decryptedStream.CopyToAsync(stream);
            }
        }
    }
}
