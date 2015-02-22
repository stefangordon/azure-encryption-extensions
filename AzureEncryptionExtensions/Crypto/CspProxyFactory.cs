using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AzureEncryptionExtensions.Crypto
{
    internal class CspProxyFactory
    {
        private class DefaultFactory : ICspProxyFactory
        {
            private readonly byte[] CspBlob;
            private readonly int KeySize;

            public DefaultFactory(byte[] cspBlob, int keySize)
            {
                CspBlob = cspBlob;
                KeySize = keySize;
            }

            public ICspProxy GetProvider()
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.ImportCspBlob(CspBlob);

                return new DisposingCspProxy(rsa, KeySize);
            }
        }

        private class CachingFactory : ICspProxyFactory
        {
            private readonly RSACryptoServiceProvider Rsa;
            private readonly int KeySize;

            public CachingFactory(RSACryptoServiceProvider rsa)
            {
                Rsa = rsa;
                KeySize = rsa.KeySize;
            }

            public ICspProxy GetProvider()
            {
                // This CSP has to survive so that it can be used again
                return new NonDisposingCspProxy(Rsa, KeySize);
            }
        }

        public static ICspProxyFactory Create(int keySize)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize))
            {
                return new DefaultFactory(rsa.ExportCspBlob(true), rsa.KeySize);
            }
        }

        public static ICspProxyFactory Create(byte[] cspBlob)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(cspBlob);
                return new DefaultFactory(cspBlob, rsa.KeySize);
            }
        }

        public static ICspProxyFactory Create(X509Certificate2 certificate, bool includePrivateKey)
        {
            ICspProxyFactory factory;
            RSACryptoServiceProvider rsa;

            if (includePrivateKey && certificate.HasPrivateKey)
                rsa = (RSACryptoServiceProvider)certificate.PrivateKey;
            else
                rsa = (RSACryptoServiceProvider)certificate.PublicKey.Key;

            // Export will fail if we attempt to export private when there is none
            // Export also fails if key is not exportable
            if (rsa.PublicOnly)
            {
                factory = new DefaultFactory(rsa.ExportCspBlob(false), rsa.KeySize);
                rsa.Dispose();
            }
            else if (rsa.CspKeyContainerInfo.Exportable)
            {
                factory = new DefaultFactory(rsa.ExportCspBlob(true), rsa.KeySize);
                rsa.Dispose();
            }
            else
            {
                factory = new CachingFactory(rsa);
            }

            return factory;
        }
    }
}
