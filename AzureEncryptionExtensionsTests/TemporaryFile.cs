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
using System.IO;

#endregion

namespace AzureBlobEncryptionTests
{
    public class TemporaryFile : IDisposable
    {
        public FileInfo fileInfo { get; set; }

        public TemporaryFile(int kilobytes)
        {
            if (kilobytes <= 0)
                throw new ArgumentOutOfRangeException("Requested size must be greater than 0.");

            string path = Path.GetTempFileName();

            using (FileStream fs = File.OpenWrite(path))
            {
                Random random = new Random();
                byte[] buffer = new byte[1024];

                for (int i = 0; i < kilobytes; i++)
                {
                    random.NextBytes(buffer);
                    fs.Write(buffer, 0, 1024);
                }
            }

            fileInfo = new FileInfo(path);
        }

        public void Dispose()
        {
            fileInfo.Refresh();
            if (fileInfo.Exists)
            {
                fileInfo.Delete();
            }
        }
    }
}
