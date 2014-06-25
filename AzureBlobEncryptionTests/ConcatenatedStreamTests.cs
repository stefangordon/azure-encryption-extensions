using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AzureBlobEncryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AzureBlobEncryptionTests
{
    [TestClass]
    public class ConcatenatedStreamTests
    {
        readonly int sampleStreamSize = 512;

        MemoryStream streamSampleOne;
        MemoryStream streamSampleTwo;

        [TestInitialize]
        public void Initialize()
        {
            // Prepare some random memory streams
            Random random = new Random();

            byte[] bufferFirst = new byte[sampleStreamSize];
            byte[] bufferSecond = new byte[sampleStreamSize];

            random.NextBytes(bufferFirst);
            random.NextBytes(bufferSecond);

            streamSampleOne = new MemoryStream(bufferFirst);
            streamSampleTwo = new MemoryStream(bufferSecond);
        }

        [TestMethod]
        public void ReadAllTest()
        {
            ConcatenatedStream cStream = new ConcatenatedStream(streamSampleOne, streamSampleTwo);

            int totalLength = (int)(sampleStreamSize * 2);

            byte[] output = new byte[totalLength];

            cStream.Read(output, 0, totalLength);

            Assert.IsTrue(
                output.Take(sampleStreamSize).SequenceEqual(streamSampleOne.ToArray()), 
                "First array does not match");

            Assert.IsTrue(
                output.Skip(sampleStreamSize).Take(sampleStreamSize).SequenceEqual(streamSampleTwo.ToArray()), 
                "Second array does not match");
        }

        [TestMethod]
        public void CanReadTest()
        {
            ConcatenatedStream cStream = new ConcatenatedStream(streamSampleOne, streamSampleTwo);

            int totalLength = (int)(sampleStreamSize * 2);

            List<byte> output = new List<byte>();

            while (cStream.CanRead)
            {
                output.Add((byte)cStream.ReadByte());
            }

            Assert.IsTrue(
                output.Take(sampleStreamSize).SequenceEqual(streamSampleOne.ToArray()),
                "First array does not match");

            Assert.IsTrue(
                output.Skip(sampleStreamSize).Take(sampleStreamSize).SequenceEqual(streamSampleTwo.ToArray()),
                "Second array does not match");
        }

    }
}
