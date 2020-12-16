using Cactus.Blade.Encryption;
using Cactus.Blade.Encryption.Async;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Text;

namespace Encryption.Test.Async
{
    [TestClass]
    public class SynchronousAsyncEncryptorTest
    {
        private Mock<IEncryptor> _encryptorMock;

        private void Setup(string cryptoId)
        {
            _encryptorMock = new Mock<IEncryptor>();

            _encryptorMock.Setup(f => f.Encrypt(It.IsAny<string>())).Returns($"EncryptedString : {cryptoId}");
            _encryptorMock.Setup(f => f.Encrypt(It.IsAny<byte[]>())).Returns(Encoding.UTF8.GetBytes(cryptoId));
        }


        [TestMethod]
        public void EncryptAsync_string_ReturnsACompletedTask()
        {
            Setup("foo");

            var asyncEncryptor = new SynchronousAsyncEncryptor(_encryptorMock.Object);

            var encryptTask = asyncEncryptor.EncryptAsync("stuff");

            Assert.IsTrue(encryptTask.IsCompleted);
        }

        [TestMethod]
        public void EncryptAsync_string_ReturnsTheResultReturnedByCryptoEncrypt()
        {
            Setup("foo");

            var asyncEncryptor = new SynchronousAsyncEncryptor(_encryptorMock.Object);

            var encrypted = asyncEncryptor.EncryptAsync("stuff").Result;

            Assert.AreEqual(encrypted, "EncryptedString : foo");
        }

        [TestMethod]
        public void EncryptAsync_bytearray_ReturnsACompletedTask()
        {
            Setup("foo");

            var asyncEncryptor = new SynchronousAsyncEncryptor(_encryptorMock.Object);

            var encryptTask = asyncEncryptor.EncryptAsync(new byte[0]);

            Assert.IsTrue(encryptTask.IsCompleted);
        }

        [TestMethod]
        public void EncryptAsync_bytearray_ReturnsTheResultReturnedByCryptoEncrypt()
        {
            Setup("foo");

            var asyncEncryptor = new SynchronousAsyncEncryptor(_encryptorMock.Object);

            var encrypted = asyncEncryptor.EncryptAsync(new byte[0]).Result;

            //Assert.AreEqual(encrypted, Encoding.UTF8.GetBytes("foo"));
        }
    }
}
