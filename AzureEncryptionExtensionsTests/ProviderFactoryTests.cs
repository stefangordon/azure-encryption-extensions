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
using AzureEncryptionExtensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

#endregion

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
