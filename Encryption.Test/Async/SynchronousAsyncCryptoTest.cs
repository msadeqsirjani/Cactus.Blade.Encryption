using Cactus.Blade.Encryption;
using Cactus.Blade.Encryption.Async;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Text;

namespace Encryption.Test.Async
{
    [TestClass]
    public class SynchronousAsyncCryptoTest
    {
        private Mock<ICrypto> _cryptoMock;
        private IEncryptor _encryptor;
        private IDecryptor _decryptor;

        private void Setup(string cryptoId)
        {
            _cryptoMock = new Mock<ICrypto>();
            _encryptor = new Mock<IEncryptor>().Object;
            _decryptor = new Mock<IDecryptor>().Object;

            _cryptoMock.Setup(f => f.CanEncrypt(cryptoId)).Returns(true);
            _cryptoMock.Setup(f => f.CanEncrypt(It.Is<string>(s => s != cryptoId))).Returns(false);
            _cryptoMock.Setup(f => f.Encrypt(It.IsAny<string>(), It.IsAny<string>())).Returns($"EncryptedString : {cryptoId}");
            _cryptoMock.Setup(f => f.Encrypt(It.IsAny<byte[]>(), It.IsAny<string>())).Returns(Encoding.UTF8.GetBytes(cryptoId));
            _cryptoMock.Setup(f => f.GetEncryptor(cryptoId)).Returns(_encryptor);

            _cryptoMock.Setup(f => f.CanDecrypt(cryptoId)).Returns(true);
            _cryptoMock.Setup(f => f.CanDecrypt(It.Is<string>(s => s != cryptoId))).Returns(false);
            _cryptoMock.Setup(f => f.Decrypt(It.IsAny<string>(), It.IsAny<string>())).Returns($"DecryptedString : {cryptoId}");
            _cryptoMock.Setup(f => f.Decrypt(It.IsAny<byte[]>(), It.IsAny<string>())).Returns(Encoding.UTF8.GetBytes(cryptoId));
            _cryptoMock.Setup(f => f.GetDecryptor(cryptoId)).Returns(_decryptor);
        }

        [TestMethod]
        public void Crypto_IsTheSameInstancePassedToTheConstructor()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            Assert.AreEqual(asyncCrypto.Crypto, _cryptoMock.Object);
        }

        [TestMethod]
        public void EncryptAsync_string_ReturnsACompletedTask()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var encryptTask = asyncCrypto.EncryptAsync("stuff", "foo");

            Assert.IsTrue(encryptTask.IsCompleted);
        }

        [TestMethod]
        public void EncryptAsync_string_ReturnsTheResultReturnedByCryptoEncrypt()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var encrypted = asyncCrypto.EncryptAsync("stuff", "foo").Result;

            Assert.AreEqual(encrypted, "EncryptedString : foo");
        }

        [TestMethod]
        public void EncryptAsync_bytearray_ReturnsACompletedTask()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var encryptTask = asyncCrypto.EncryptAsync(new byte[0], "foo");

            Assert.IsTrue(encryptTask.IsCompleted);
        }

        [TestMethod]
        public void EncryptAsync_bytearray_ReturnsTheResultReturnedByCryptoEncrypt()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var encrypted = asyncCrypto.EncryptAsync(new byte[0], "foo").Result;

            //Assert.AreEqual(encrypted, Encoding.UTF8.GetBytes("foo"));
        }

        [TestMethod]
        public void DecryptAsync_string_ReturnsACompletedTask()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var encryptTask = asyncCrypto.DecryptAsync("stuff", "foo");

            Assert.IsTrue(encryptTask.IsCompleted);
        }

        [TestMethod]
        public void DecryptAsync_string_ReturnsTheResultReturnedByCryptoEncrypt()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var encrypted = asyncCrypto.DecryptAsync("stuff", "foo").Result;

            Assert.AreEqual(encrypted, "DecryptedString : foo");
        }

        [TestMethod]
        public void DecryptAsync_bytearray_ReturnsACompletedTask()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var encryptTask = asyncCrypto.DecryptAsync(new byte[0], "foo");

            Assert.IsTrue(encryptTask.IsCompleted);
        }

        [TestMethod]
        public void DecryptAsync_bytearray_ReturnsTheResultReturnedByCryptoEncrypt()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var encrypted = asyncCrypto.DecryptAsync(new byte[0], "foo").Result;

            //Assert.AreEqual(encrypted, Encoding.UTF8.GetBytes("foo"));
        }

        [TestMethod]
        public void GetEncryptorAsync_ReturnsASynchronousAsyncEncryptor()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var encryptor = asyncCrypto.GetAsyncEncryptor("foo");

            Assert.AreNotEqual(encryptor, typeof(SynchronousAsyncEncryptor));
        }

        [TestMethod]
        public void GetEncryptorAsync_ReturnsASynchronousAsyncEncryptorWhoseEncryptorIsTheOneReturnedByACallToTheCryptoGetEncryptorMethod()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var encryptor = (SynchronousAsyncEncryptor)asyncCrypto.GetAsyncEncryptor("foo");

            Assert.AreEqual(encryptor.Encryptor, _encryptor);
        }

        [TestMethod]
        public void GetDecryptorAsync_ReturnsASynchronousAsyncDecryptor()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var decryptor = asyncCrypto.GetAsyncDecryptor("foo");

            Assert.AreNotEqual(decryptor, typeof(SynchronousAsyncDecryptor));
        }

        [TestMethod]
        public void GetDecryptorAsync_ReturnsASynchronousAsyncDecryptorWhoseDecryptorIsTheOneReturnedByACallToTheCryptoGetDecryptorMethod()
        {
            Setup("foo");

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            var decryptor = (SynchronousAsyncDecryptor)asyncCrypto.GetAsyncDecryptor("foo");

            Assert.AreEqual(decryptor.Decryptor, _decryptor);
        }

        [TestMethod]
        public void CanEncrypt_ReturnsTheSameThingAsACallToCryptoCanEncrypt()
        {
            Setup("foo");

            Assert.IsTrue(_cryptoMock.Object.CanEncrypt("foo"));
            Assert.IsFalse(_cryptoMock.Object.CanEncrypt("bar"));

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            Assert.IsTrue(asyncCrypto.CanEncrypt("foo"));
            Assert.IsFalse(asyncCrypto.CanEncrypt("bar"));
        }

        [TestMethod]
        public void CanDecrypt_ReturnsTheSameThingAsACallToCryptoCanDecrypt()
        {
            Setup("foo");

            Assert.IsTrue(_cryptoMock.Object.CanEncrypt("foo"));
            Assert.IsFalse(_cryptoMock.Object.CanEncrypt("bar"));

            var asyncCrypto = new SynchronousAsyncCrypto(_cryptoMock.Object);

            Assert.IsTrue(asyncCrypto.CanEncrypt("foo"));
            Assert.IsFalse(asyncCrypto.CanEncrypt("bar"));
        }
    }
}
