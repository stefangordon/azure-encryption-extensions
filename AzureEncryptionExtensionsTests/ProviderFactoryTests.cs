using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AzureEncryptionExtensions;
using AzureEncryptionExtensions.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

// Provider Factory is heavily tested in the individual
// provider test classes.
// This is just for generic exception handling testing.
namespace AzureBlobEncryptionTests
{
    [TestClass]
    public class ProviderFactoryTests
    {

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void InvalidPathTest()
        {
            var provider = ProviderFactory.CreateProviderFromKeyFile("invalid.txt");
           
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidKeyFileException))]
        public void InvalidStringTest()
        {
            var provider = ProviderFactory.CreateProviderFromKeyFileString("Some random text.");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EmptyStringTest()
        {
            var provider = ProviderFactory.CreateProviderFromKeyFileString(string.Empty);
        }

    }
}
