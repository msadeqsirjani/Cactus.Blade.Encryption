using System;
using System.Linq;
using System.Security.Cryptography;

namespace Cactus.Blade.Encryption.Symmetric
{
    internal static class SymmetricAlgorithmExtension
    {
        public static System.Security.Cryptography.SymmetricAlgorithm CreateSymmetricAlgorithm(
            this SymmetricAlgorithm algorithm)
        {
            return algorithm switch
            {
                SymmetricAlgorithm.Aes => Aes.Create(),
                SymmetricAlgorithm.DES => DES.Create(),
                SymmetricAlgorithm.RC2 => RC2.Create(),
                SymmetricAlgorithm.Rijndael => Rijndael.Create(),
                SymmetricAlgorithm.TripleDES => TripleDES.Create(),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm,
                    $@"Invalid SymmetricAlgorithm. Valid values are: {
                        string.Join(", ", Enum.GetValues(typeof(SymmetricAlgorithm))
                            .Cast<SymmetricAlgorithm>().Select(x => x.ToString()))}.")
            };
        }
    }
}
