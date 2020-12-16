using Cactus.Blade.Encryption;
using Cactus.Blade.Encryption.Async;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Encryption.Test.Async
{
    [TestClass]
    public class AsAsyncExtension
    {
        [TestMethod]
        public void AsAsync_GivenAnObjectThatImplementsIAsyncCryptoTheSameObjectIsReturned()
        {
            var crypto = new TestCrypto();

            var asyncCrypto = crypto.AsAsync();

            Assert.AreEqual(asyncCrypto, crypto);
        }

        [TestMethod]
        public void AsAsync_GivenAnObjectThatDoesNotImplementsIAsyncCryptoASynchronousAsyncCryptoIsReturned()
        {
            var crypto = new Mock<ICrypto>().Object;

            var asyncCrypto = crypto.AsAsync();

            Assert.AreEqual(asyncCrypto.GetType(), typeof(SynchronousAsyncCrypto));
        }

        [TestMethod]
        public void AsAsync_GivenAnObjectThatDoesNotImplementsIAsyncCryptoTheSynchronousAsyncCryptoUsesTheOriginalICrypto()
        {
            var crypto = new Mock<ICrypto>().Object;

            var asyncCrypto = (SynchronousAsyncCrypto)crypto.AsAsync();

            Assert.AreEqual(asyncCrypto.Crypto, crypto);
        }

        [TestMethod]
        public void AsAsync_MultipleCallsWithTheSameObjectThatDoesNotImplementIAsyncCryptoReturnTheSameObjectEachTime()
        {
            var crypto = new Mock<ICrypto>().Object;

            var asyncCrypto1 = crypto.AsAsync();
            var asyncCrypto2 = crypto.AsAsync();

            Assert.AreEqual(asyncCrypto1, asyncCrypto2);
        }

        private class TestCrypto : ICrypto, IAsyncCrypto
        {
            public string Encrypt(string plainText, string credentialName)
            {
                throw new NotImplementedException();
            }

            public string Decrypt(string cipherText, string credentialName)
            {
                throw new NotImplementedException();
            }

            public byte[] Encrypt(byte[] plainText, string credentialName)
            {
                throw new NotImplementedException();
            }

            public byte[] Decrypt(byte[] cipherText, string credentialName)
            {
                throw new NotImplementedException();
            }

            public IEncryptor GetEncryptor(string credentialName)
            {
                throw new NotImplementedException();
            }

            public IDecryptor GetDecryptor(string credentialName)
            {
                throw new NotImplementedException();
            }

            public Task<string> EncryptAsync(string plainText, string credentialName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<string> DecryptAsync(string cipherText, string credentialName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<byte[]> EncryptAsync(byte[] plainText, string credentialName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<byte[]> DecryptAsync(byte[] cipherText, string credentialName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public IAsyncEncryptor GetAsyncEncryptor(string credentialName)
            {
                throw new NotImplementedException();
            }

            public IAsyncDecryptor GetAsyncDecryptor(string credentialName)
            {
                throw new NotImplementedException();
            }

            bool IAsyncCrypto.CanEncrypt(string credentialName)
            {
                throw new NotImplementedException();
            }

            bool IAsyncCrypto.CanDecrypt(string credentialName)
            {
                throw new NotImplementedException();
            }

            bool ICrypto.CanEncrypt(string credentialName)
            {
                throw new NotImplementedException();
            }

            bool ICrypto.CanDecrypt(string credentialName)
            {
                throw new NotImplementedException();
            }
        }
    }
}
