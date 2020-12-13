using System.Security.Cryptography;
using System.Threading;

namespace Cactus.Blade.Encryption.Symmetric
{
    internal class Range
    {
        private static readonly ThreadLocal<RandomNumberGenerator> Instance =
            new ThreadLocal<RandomNumberGenerator>(RandomNumberGenerator.Create);

        public static byte[] GetBytes(int size)
        {
            var data = new byte[size];

            Instance.Value.GetBytes(data);

            return data;
        }
    }
}
