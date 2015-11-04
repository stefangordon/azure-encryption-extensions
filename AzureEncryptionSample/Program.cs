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
using System.Security.Cryptography.X509Certificates;

#endregion

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
            Samples.UploadEncryptedFileAsymmetric(@"SampleFiles\catbread.jpg", certificate, container);

            // Load certificate
            // Certificates are intentionally disposed of after creating providers in most cases
            // So we must load this again for this round-trip sample
            certificate = new X509Certificate2(@"SampleCertificates\4096.pfx", string.Empty, X509KeyStorageFlags.Exportable);

            // Download
            Console.WriteLine("Downloading and decrypting file using saved key");
            Samples.DownloadEncryptedFileAsymmetric(@"decrypted_catbread2.jpg", certificate, container);
        }



    }
}
