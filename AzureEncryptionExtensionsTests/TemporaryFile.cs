using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
