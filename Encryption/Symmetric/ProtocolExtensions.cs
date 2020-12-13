using System;
using System.IO;

namespace Cactus.Blade.Encryption.Symmetric
{
    internal static class ProtocolExtensions
    {
        public static void WriteCipherTextHeader(this Stream stream, byte[] iv)
        {
            stream.WriteByte(1);
            stream.WriteByte((byte)(iv.Length & 0xFF));
            stream.WriteByte((byte)(iv.Length >> 8));
            stream.Write(iv, 0, iv.Length);
        }

        public static byte[] ReadIvFromCipherTextHeader(this Stream stream)
        {
            var protocolVersion = stream.ReadByte();

            if (protocolVersion != 1)
                throw new InvalidOperationException("Unknown protocol version (only version 1 is supported): " + protocolVersion);

            var ivSize = (ushort)(stream.ReadByte() | (stream.ReadByte() << 8));
            var iv = new byte[ivSize];

            stream.Read(iv, 0, ivSize);

            return iv;
        }

        public static bool IsEncrypted(this byte[] cipherText)
        {
            if (cipherText.Length < 3 || cipherText[0] != 1)
                return false;

            var ivSize = (ushort)(cipherText[1] | (cipherText[2] << 8));

            switch (ivSize)
            {
                case 8:
                case 16:
                    return cipherText.Length >= 3 + ivSize;
            }

            return false;
        }
    }
}
