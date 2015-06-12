using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AzureEncryptionExtensions.Crypto
{
    internal interface ICspProxyFactory
    {
        ICspProxy GetProvider();
    }
}
