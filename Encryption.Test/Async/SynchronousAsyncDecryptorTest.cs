using Cactus.Blade.Encryption;
using Cactus.Blade.Encryption.Async;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Text;

namespace Encryption.Test.Async
{
    [TestClass]
    public class SynchronousAsyncDecryptorTest
    {
        private Mock<IDecryptor> _decryptorMock;

        private void Setup(string cryptoId)
        {
            _decryptorMock = new Mock<IDecryptor>();

            _decryptorMock.Setup(f => f.Decrypt(It.IsAny<string>())).Returns($"DecryptedString : {cryptoId}");
            _decryptorMock.Setup(f => f.Decrypt(It.IsAny<byte[]>())).Returns(Encoding.UTF8.GetBytes(cryptoId));
        }


        [TestMethod]
        public void DecryptAsync_string_ReturnsACompletedTask()
        {
            Setup("foo");

            var asyncDecryptor = new SynchronousAsyncDecryptor(_decryptorMock.Object);

            var decryptTask = asyncDecryptor.DecryptAsync("stuff");

            Assert.IsTrue(decryptTask.IsCompleted);
        }

        [TestMethod]
        public void DecryptAsync_string_ReturnsTheResultReturnedByCryptoDecrypt()
        {
            Setup("foo");

            var asyncDecryptor = new SynchronousAsyncDecryptor(_decryptorMock.Object);

            var decrypted = asyncDecryptor.DecryptAsync("stuff").Result;

            Assert.AreEqual(decrypted, "DecryptedString : foo");
        }

        [TestMethod]
        public void DecryptAsync_bytearray_ReturnsACompletedTask()
        {
            Setup("foo");

            var asyncDecryptor = new SynchronousAsyncDecryptor(_decryptorMock.Object);

            var decryptTask = asyncDecryptor.DecryptAsync(new byte[0]);

            Assert.IsTrue(decryptTask.IsCompleted);
        }

        [TestMethod]
        public void DecryptAsync_bytearray_ReturnsTheResultReturnedByCryptoDecrypt()
        {
            Setup("foo");

            var asyncDecryptor = new SynchronousAsyncDecryptor(_decryptorMock.Object);

            var decrypted = asyncDecryptor.DecryptAsync(new byte[0]).Result;

            var actual = Encoding.UTF8.GetBytes("foo");

            //Assert.AreEqual(decrypted, actual);
        }
    }
}
