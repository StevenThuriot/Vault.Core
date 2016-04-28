using System.IO;
using System.Security.Cryptography;
using Vault.Core.Extensions;

namespace Vault.Core
{
    unsafe static partial class Security
    {
        public static byte[] EncryptString(string input, byte[] password, ushort saltSize, int iterations)
        {
            fixed (char* inputPtr = input)
                return EncryptString(inputPtr, input.Length, password, saltSize, iterations);
        }

        public static byte[] EncryptString(char* input, int length, byte[] password, ushort saltSize, int iterations)
        {
            if (length == 0) return new byte[0];

            var bytes = new byte[length * sizeof(char)];

            fixed (void* ptr = bytes)
                UnsafeNativeMethods.memcpy(ptr, input, bytes.Length);

            var result = Encrypt(bytes, password, saltSize, iterations);
            bytes.Clear();

            return result;
        }

        public static string DecryptString(byte[] input, byte[] password, int iterations)
        {
            if (input.Length == 0) return "";

            var bytes = Decrypt(input, password, iterations);

            var resultArray = new char[bytes.Length / sizeof(char)];

            fixed (void* bytesPtr = bytes, resultPtr = resultArray)
                UnsafeNativeMethods.memcpy(resultPtr, bytesPtr, bytes.Length);

            bytes.Clear();

            var result = new string(resultArray);
            resultArray.Clear();

            return result;
        }

        public static byte[] Encrypt(byte[] input, byte[] password, ushort saltSize, int iterations)
        {
            var salt = CreateSalt(saltSize);

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.BlockSize = 128;
                aes.KeySize = 256;
                using (var key = new Rfc2898DeriveBytes(password, salt, iterations))
                {
                    aes.Key = key.GetBytes(16);
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    aes.GenerateIV();

                    using (var memStream = new MemoryStream())
                    {
                        //While a byte would suffice, 
                        //we'll take the sure-thing and just use a ushort instead, this allows a key-length of 65535 tokens.
                        var bytes = new byte[sizeof(ushort)];
                        
                        fixed (void* b = bytes)
                            *((ushort*)b) = saltSize;
                        memStream.Write(bytes, 0, bytes.Length);

                        fixed (void* b = bytes)
                            *((ushort*)b) = (ushort)aes.IV.Length;
                        memStream.Write(bytes, 0, bytes.Length);

                        memStream.Write(salt, 0, salt.Length);
                        memStream.Write(aes.IV, 0, aes.IV.Length);

                        using (var encryptor = aes.CreateEncryptor())
                        using (var cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(input, 0, input.Length);
                            cryptoStream.FlushFinalBlock();

                            var encrypted = memStream.ToArray();
                            return encrypted;
                        }
                    }
                }
            }
        }

        public static byte[] Decrypt(byte[] input, byte[] password, int iterations)
        {
            if (input.Length == 0) return new byte[0];

            fixed (void* p = input)
            {
                var ptr = (ushort*)p;

                var saltLength = *ptr++;
                var ivLength = *ptr++;

                var bytePtr = (byte*)ptr;

                var salt = new byte[saltLength];
                fixed (void* saltPtr = salt)
                    UnsafeNativeMethods.memcpy(saltPtr, bytePtr, saltLength);

                bytePtr += saltLength;

                var iv = new byte[ivLength];
                fixed (void* ivPtr = iv)
                    UnsafeNativeMethods.memcpy(ivPtr, bytePtr, ivLength);

                bytePtr += ivLength;

                var content = new byte[input.Length - sizeof(ushort) * 2 - saltLength - ivLength];
                fixed (void* contentPtr = content)
                    UnsafeNativeMethods.memcpy(contentPtr, bytePtr, content.Length);

                using (var aes = new AesCryptoServiceProvider())
                {
                    aes.BlockSize = 128;
                    aes.KeySize = 256;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    aes.IV = iv;

                    using (var key = new Rfc2898DeriveBytes(password, salt, iterations))
                    {
                        aes.Key = key.GetBytes(16);

                        using (var decryptor = aes.CreateDecryptor())
                        {
                            var result = decryptor.TransformFinalBlock(content, 0, content.Length);

                            salt.Clear();
                            iv.Clear();
                            content.Clear();

                            return result;
                        }
                    }
                }
            }
        }

        static byte[] CreateSalt(ushort size)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var salt = new byte[size];

                rng.GetBytes(salt);

                return salt;
            }
        }
    }
}