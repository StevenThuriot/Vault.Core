using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace Vault
{
    public unsafe static class Security
    {
        const int DEFAULT_ITERATIONS = 1675; //Randomly picked number
        const int DEFAULT_SALTSIZE = 8;

        static string ResolveIndexFile(string path) => Path.Combine(Path.GetDirectoryName(path), Path.GetFileNameWithoutExtension(path)) + ".idx";

        public static void MergeFile(IDictionary<string, SecureString> values, string path, byte[] password, bool writeOffsets = true, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS, bool encryptResult = true)
        {
            var dictionary = DecryptFile(path, password, iterations, encryptResult);
            var original = dictionary.Values.ToArray();

            foreach (var kvp in values)
                dictionary[kvp.Key] = kvp.Value;

            EncryptFile(dictionary, path, password, writeOffsets, saltSize, iterations, encryptResult);

            //Clean up decrypted keys, make user clean up their own.
            foreach (var secureString in original)
                secureString.Dispose();
        }

        public static void EncryptFile(IDictionary<string, SecureString> values, string path, byte[] password, bool writeOffsets = true, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS, bool encryptResult = true)
        {
            byte[] bytes;

            if (writeOffsets)
            {
                byte[] offsets;
                bytes = EncryptDictionary(values, password, out offsets, saltSize, iterations, encryptResult);
                string idx = ResolveIndexFile(path);
                File.WriteAllBytes(idx, offsets);
                offsets.Clear();
            }
            else
            {
                bytes = EncryptDictionary(values, password, saltSize, iterations, encryptResult);
            }

            File.WriteAllBytes(path, bytes);

            bytes.Clear();
        }

        public static SecureString DecryptFile(string path, string key, byte[] password, int iterations = DEFAULT_ITERATIONS, bool inputIsEncrypted = true)
        {
            if (!File.Exists(path)) return null;

            var idx = ResolveIndexFile(path);

            if (!inputIsEncrypted && File.Exists(idx)) //If encrypted, we can't use the idx file since we can't just read keys from the stream.
            {
                var indexes = File.ReadAllBytes(idx);

                if (indexes.Length != 0)
                {
                    var keyBytes = new byte[key.Length * sizeof(char)];

                    fixed (void* keyPtr = key, destPtr = keyBytes)
                        UnsafeNativeMethods.memcpy(destPtr, keyPtr, keyBytes.Length);

                    using (var fs = File.OpenRead(path))
                    {
                        fixed (byte* b = indexes)
                        {
                            var ptr = (ushort*)b;

                            var length = new byte[sizeof(ushort)];
                            do
                            {
                                fs.Seek(*ptr, SeekOrigin.Begin);
                                fs.Read(length, 0, sizeof(ushort));

                                fixed (byte* k = length)
                                    if (*(ushort*)k != keyBytes.Length)
                                {
                                    ptr++;
                                    continue;
                                }

                                byte[] content;

                                fixed (byte* k = length)
                                    content = new byte[*(ushort*)k];

                                fs.Read(length, 0, length.Length); //contentLength
                                fs.Read(content, 0, content.Length); //key

                                if (UnsafeNativeMethods.ByteEquals(content, keyBytes)) //check if keys match
                                {
                                    fixed (byte* k = length)
                                        content = new byte[*(ushort*)k]; //content length

                                    fs.Read(content, 0, content.Length);

                                    var secureString = DecryptSecureString(content, password, iterations);

                                    content.Clear();

                                    return secureString;
                                }

                                ptr++;
                            } while (((byte*)ptr - b) != indexes.Length);
                        }
                    }
                }

                return null;
            }
            
            var bytes = File.ReadAllBytes(path);
            var result = DecryptDictionary(bytes, key, password, iterations, inputIsEncrypted);
            bytes.Clear();

            return result;
        }

        public static IDictionary<string, SecureString> DecryptFile(string path, byte[] password, int iterations = DEFAULT_ITERATIONS, bool inputIsEncrypted = true)
        {
            if (!File.Exists(path)) return new Dictionary<string, SecureString>();

            var bytes = File.ReadAllBytes(path);
            var result = DecryptDictionary(bytes, password, iterations, inputIsEncrypted);
            bytes.Clear();

            return result;
        }

        public static byte[] EncryptDictionary(IDictionary<string, SecureString> values, byte[] password, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS, bool encryptResult = true)
        {
            byte[] offsets;
            var result = EncryptDictionary(values, password, out offsets, saltSize, iterations, encryptResult);

            offsets.Clear();

            return result;
        }

        public static byte[] EncryptDictionary(IDictionary<string, SecureString> values, byte[] password, out byte[] offsets, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS, bool encryptResult = true)
        {
            if (values.Count == 0) return offsets = new byte[0];

            offsets = new byte[values.Count * sizeof(ushort)];

            using (var stream = new MemoryStream())
            {
                var counter = 0;
                ushort offset = 0;

                foreach (var kvp in values)
                {
                    var key = kvp.Key;
                    var keyArray = new byte[key.Length * sizeof(char)];

                    fixed (void* keyPtr = key)
                    fixed (void* destPtr = keyArray)
                        UnsafeNativeMethods.memcpy(destPtr, keyPtr, keyArray.Length);

                    var encrypted = EncryptSecureString(kvp.Value, password, saltSize, iterations);

                    var index = new byte[sizeof(ushort)];

                    fixed (void* ptr = index)
                        *((ushort*)ptr) = (ushort)keyArray.Length;
                    stream.Write(index, 0, sizeof(ushort));

                    fixed (void* ptr = index)
                        *((ushort*)ptr) = (ushort)encrypted.Length;
                    stream.Write(index, 0, sizeof(ushort));

                    stream.Write(keyArray, 0, keyArray.Length);
                    stream.Write(encrypted, 0, encrypted.Length);

                    encrypted.Clear();

                    fixed (byte* b = &offsets[counter])
                        *((ushort*)b) = offset;

                    counter += sizeof(ushort);

                    offset = (ushort)(offset + (sizeof(ushort) * 2) + keyArray.Length + encrypted.Length);
                }

                var result = stream.ToArray();

                if (!encryptResult) return result;

                var originalOffsets = offsets;
                offsets = Encrypt(offsets, password, saltSize, iterations);
                originalOffsets.Clear();

                var encrypt = Encrypt(result, password);
                result.Clear();

                return encrypt;
            }
        }

        public static SecureString DecryptDictionary(byte[] input, string dictionaryKey, byte[] password, int iterations = DEFAULT_ITERATIONS, bool inputIsEncrypted = true, StringComparer comparer = null)
        {
            if (input.Length == 0) return null;

            if (comparer == null)
                comparer = StringComparer.Ordinal;

            var src = input;
            if (inputIsEncrypted)
            {
                src = Decrypt(input, password, iterations);
                input.Clear();
            }

            fixed (byte* ptr = src)
            {
                var p = ptr;

                do
                {
                    var keyPtr = (ushort*)p;

                    var keySize = *keyPtr++;
                    var contentSize = *keyPtr++;

                    p = (byte*)keyPtr;

                    var key = new char[keySize / sizeof(char)];

                    fixed (void* k = key)
                        UnsafeNativeMethods.memcpy(k, p, keySize);

                    p += keySize;

                    var stringKey = new string(key);
                    key.Clear();

                    if (comparer.Equals(stringKey, dictionaryKey))
                    {
                        var content = new byte[contentSize];
                        fixed (void* contentPtr = content)
                        {
                            UnsafeNativeMethods.memcpy(contentPtr, p, contentSize);
                            var secureString = DecryptSecureString(content, password, iterations);

                            content.Clear();

                            return secureString;
                        }
                    }

                    p += contentSize;


                } while (p - ptr != input.Length);
            }

            throw new KeyNotFoundException(string.Format("Key '{0}' was not found in the input array.", dictionaryKey));
        }

        public static IDictionary<string, SecureString> DecryptDictionary(byte[] input, byte[] password, int iterations = DEFAULT_ITERATIONS, bool inputIsEncrypted = true)
        {
            var result = new Dictionary<string, SecureString>();

            if (input.Length == 0) return result;

            var src = input;
            if (inputIsEncrypted)
            {
                src = Decrypt(input, password, iterations);
                input.Clear();
            }

            fixed (byte* ptr = src)
            {
                var p = ptr;

                do
                {
                    var keyPtr = (ushort*)p;

                    var keySize = *keyPtr++;
                    var contentSize = *keyPtr++;

                    p = (byte*)keyPtr;

                    var key = new char[keySize / sizeof(char)];

                    fixed (void* k = key)
                        UnsafeNativeMethods.memcpy(k, p, keySize);

                    p += keySize;

                    var content = new byte[contentSize];
                    fixed (void* contentPtr = content)
                    {
                        UnsafeNativeMethods.memcpy(contentPtr, p, contentSize);

                        result[new string(key)] = DecryptSecureString(content, password, iterations);

                        key.Clear();
                        content.Clear();
                    }

                    p += contentSize;

                } while ((p - ptr) != src.Length);
            }

            return result;
        }

        public static byte[] EncryptSecureString(SecureString input, byte[] password, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS)
        {
            var ptr = IntPtr.Zero;
            byte[] bytes = null;

            try
            {
                ptr = Marshal.SecureStringToBSTR(input);
                bytes = new byte[input.Length * 2];

                fixed (void* b = bytes)
                    UnsafeNativeMethods.memcpy(b, ptr.ToPointer(), bytes.Length);

                return Encrypt(bytes, password, saltSize, iterations);
            }
            finally
            {
                if (bytes != null)
                    bytes.Clear();

                if (ptr != IntPtr.Zero) Marshal.ZeroFreeBSTR(ptr);
            }
        }

        public static SecureString DecryptSecureString(byte[] input, byte[] password, int iterations = DEFAULT_ITERATIONS)
        {
            var bytes = Decrypt(input, password, iterations);

            SecureString secureString;
            fixed (byte* ptr = bytes)
                secureString = new SecureString((char*)ptr, bytes.Length / sizeof(char));

            secureString.MakeReadOnly();
            bytes.Clear();

            return secureString;
        }

        public static byte[] EncryptString(string input, byte[] password, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS)
        {
            fixed (char* inputPtr = input)
                return EncryptString(inputPtr, input.Length, password, saltSize, iterations);
        }

        public static byte[] EncryptString(char* input, int length, byte[] password, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS)
        {
            var bytes = new byte[length * sizeof(char)];

            fixed (void* ptr = bytes)
                UnsafeNativeMethods.memcpy(ptr, input, bytes.Length);

            var result = Encrypt(bytes, password, saltSize, iterations);
            bytes.Clear();

            return result;
        }

        public static string DecryptString(byte[] input, byte[] password, int iterations = DEFAULT_ITERATIONS)
        {
            var bytes = Decrypt(input, password, iterations);

            var resultArray = new char[bytes.Length / sizeof(char)];

            fixed (void* bytesPtr = bytes)
            fixed (void* resultPtr = resultArray)
                UnsafeNativeMethods.memcpy(resultPtr, bytesPtr, bytes.Length);

            bytes.Clear();

            var result = new string(resultArray);
            resultArray.Clear();

            return result;
        }


        public static byte[] Encrypt(byte[] input, byte[] password, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS)
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
                        //While a byte would suffice, we'll take the sure-thing and just use a ushort instead.
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

        public static byte[] Decrypt(byte[] input, byte[] password, int iterations = DEFAULT_ITERATIONS)
        {
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
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [TargetedPatchingOptOut("Performance critical to inline across NGen image boundaries")]
        static void Clear<T>(this T[] bytes)
        {
            Array.Clear(bytes, 0, bytes.Length);
        }
    }
}