using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AzureEncryptionSample
{
    class Program
    {
        static void Main(string[] args)
        {
            RunSymmetricUploadAndDownload();

            Console.WriteLine();

            RunAsymmetricUploadAndDownload();

            Console.WriteLine("\nDone.  Press any key to exit.");

            Console.ReadKey();
        }

        private static void RunSymmetricUploadAndDownload()
        {
            // Get container
            Console.WriteLine("Uploading an image to blob storage and encrypting using a randomly generated AES256 key.");
            Console.WriteLine("Retrieving blob container...");
            var container = Samples.GetAzureContainer();

            // Upload
            Console.WriteLine(@"Encrypting and uploading image \SampleFiles\catbread.jpg");
            Samples.UploadEncryptedFileSymmetric(@"SampleFiles\catbread.jpg", container);

            // Download
            Console.WriteLine("Downloading and decrypting file using saved key");
            Samples.DownloadEncryptedFileSymmetric(@"decrypted_catbread.jpg", container);
        }

        private static void RunAsymmetricUploadAndDownload()
        {
            // Get container
            Console.WriteLine("Uploading an image to blob storage and encrypting using a 4096bit certificate.");
            Console.WriteLine("Retrieving blob container...");
            var container = Samples.GetAzureContainer();

            // Load certificate
            X509Certificate2 certificate = new X509Certificate2(@"SampleCertificates\4096.pfx", string.Empty, X509KeyStorageFlags.Exportable);

            // Upload
            Console.WriteLine(@"Encrypting and uploading image \SampleFiles\catbread.jpg");
            Samples.UploadEncryptedFileSymmetric(@"SampleFiles\catbread.jpg", container);

            // Download
            Console.WriteLine("Downloading and decrypting file using saved key");
            Samples.DownloadEncryptedFileSymmetric(@"decrypted_catbread2.jpg", container);
        }



    }
}
