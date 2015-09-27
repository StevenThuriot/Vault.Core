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





        #region Key Value Encryption

        public static void MergeFile(IDictionary<string, SecureString> values, string path, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS)
        {
            var dictionary = DecryptFile(path, password, iterations, options);
            var original = dictionary.Values.ToArray();

            foreach (var kvp in values)
                dictionary[kvp.Key] = kvp.Value;

            EncryptFile(dictionary, path, password, options, saltSize, iterations);

            //Clean up decrypted keys, make user clean up their own.
            foreach (var secureString in original)
                secureString.Dispose();
        }

        public static void EncryptFile(IDictionary<string, SecureString> values, string path, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS)
        {
            byte[] bytes;

            if (options.WriteOffsets())
            {
                byte[] offsets;
                bytes = EncryptDictionary(values, password, out offsets, options, saltSize, iterations);
                string idx = ResolveIndexFile(path);
                File.WriteAllBytes(idx, offsets);
                offsets.Clear();
            }
            else
            {
                bytes = EncryptDictionary(values, password, options, saltSize, iterations);
            }

            using (FileStream fs = new FileStream(path, FileMode.Create))
            {
                //fs.Write(new byte[] { (byte)options }, 0, 1);
                fs.Write(bytes, 0, bytes.Length);
            }

            bytes.Clear();
        }

        public static SecureString DecryptFile(string path, string key, byte[] password, int iterations = DEFAULT_ITERATIONS, EncryptionOptions options = EncryptionOptions.Default)
        {
            if (!File.Exists(path)) throw new FileNotFoundException("File not found", path);

            var idx = ResolveIndexFile(path);

            if (File.Exists(idx))
            {
                return DecryptUsingIndexFile(path, key, password, iterations, options, idx);
            }

            var bytes = File.ReadAllBytes(path);
            var result = DecryptDictionary(bytes, key, password, options, iterations);
            bytes.Clear();

            return result;
        }

        static SecureString DecryptUsingIndexFile(string path, string key, byte[] password, int iterations, EncryptionOptions options, string idx)
        {
            var indexes = File.ReadAllBytes(idx);

            if (indexes.Length != 0)
            {
                var keyBytes = new byte[key.Length * sizeof(char)];

                fixed (void* keyPtr = key, destPtr = keyBytes)
                    UnsafeNativeMethods.memcpy(destPtr, keyPtr, keyBytes.Length);

                if (options.IsResultEncrypted())
                {
                    indexes = Decrypt(indexes, password, iterations);

                    fixed (byte* b = indexes)
                    {
                        var ptr = (ushort*)b;

                        do
                        {
                            var offset = *ptr;
                            var length = *++ptr;
                            var keyLengthInBytes = length * sizeof(char);

                            ptr++;

                            if (length != key.Length)
                            {
                                var bytePtr = (byte*)ptr;
                                bytePtr += keyLengthInBytes;
                                ptr = (ushort*)bytePtr;
                                continue;
                            }


                            var keyArray = new byte[keyLengthInBytes];

                            fixed (byte* c = keyArray)
                            {
                                UnsafeNativeMethods.memcpy(c, ptr, keyArray.Length);

                                if (UnsafeNativeMethods.memcmp(keyArray, keyBytes))
                                {
                                    keyArray.Clear();
                                    //Key matches, read content from file

                                    //Since the entire file has been encoded before saving, we need to read all the bytes and decode them first.
                                    var fileContent = File.ReadAllBytes(path);

                                    var decryptedFile = Decrypt(fileContent, password, iterations);

                                    fileContent.Clear();

                                    var contentLength = decryptedFile[offset + sizeof(ushort)];
                                    var content = new byte[contentLength];

                                    fixed (byte* dest = content, src = decryptedFile)
                                    {
                                        var srcPtr = src + offset + sizeof(ushort) * 2 + keyLengthInBytes;
                                        UnsafeNativeMethods.memcpy(dest, srcPtr, content.Length);
                                    }

                                    var secureString = DecryptSecureString(content, password, iterations);

                                    content.Clear();

                                    return secureString;
                                }
                            }

                            keyArray.Clear();

                            var bytesPtr = (byte*)ptr;
                            bytesPtr += keyLengthInBytes;
                            ptr = (ushort*)bytesPtr;

                        } while ((byte*)ptr - b != indexes.Length);
                    }
                }
                else
                {
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
                                {
                                    if (*(ushort*)k != keyBytes.Length)
                                    {
                                        ptr++;
                                        continue;
                                    }
                                }

                                byte[] content;

                                fixed (byte* k = length)
                                    content = new byte[*(ushort*)k];

                                fs.Read(length, 0, length.Length); //contentLength
                                fs.Read(content, 0, content.Length); //key

                                if (UnsafeNativeMethods.memcmp(content, keyBytes)) //check if keys match
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
            }

            throw new KeyNotFoundException($"Key '{key}' was not found in the input array.");
        }

        public static IDictionary<string, SecureString> DecryptFile(string path, byte[] password, int iterations = DEFAULT_ITERATIONS, EncryptionOptions options = EncryptionOptions.Default)
        {
            if (!File.Exists(path)) throw new FileNotFoundException("File not found", path);

            var bytes = File.ReadAllBytes(path);
            
            var result = DecryptDictionary(bytes, password, options, iterations);
            bytes.Clear();

            return result;
        }

        public static byte[] EncryptDictionary(IDictionary<string, SecureString> values, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS)
        {
            byte[] offsets;
            var result = EncryptDictionary(values, password, out offsets, options, saltSize, iterations);

            offsets.Clear();

            return result;
        }

        public static byte[] EncryptDictionary(IDictionary<string, SecureString> values, byte[] password, out byte[] offsets, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS)
        {
            if (values.Count == 0) return offsets = new byte[0];

            var offsetArrayLength = values.Count * sizeof(ushort);

            var resultIsEncrypted = options.IsResultEncrypted();

            if (resultIsEncrypted)
            {
                //Write keys in idx file when result is encrypted
                offsetArrayLength += values.Keys.Sum(x => x.Length) * sizeof(char) + values.Keys.Count * sizeof(ushort);
            }

            offsets = new byte[offsetArrayLength];

            using (var stream = new MemoryStream())
            {
                var counter = 0;
                ushort offset = 0;

                var keysShouldBeEncrypted = options.AreKeysEncrypted();

                foreach (var kvp in values)
                {
                    var key = kvp.Key;
                    
                    byte[] keyArray;
                    if (keysShouldBeEncrypted)
                    {
                        keyArray = EncryptString(key, password, saltSize, iterations);
                    }
                    else
                    {
                        keyArray = new byte[key.Length * sizeof(char)];

                        fixed (void* keyPtr = key, destPtr = keyArray)
                            UnsafeNativeMethods.memcpy(destPtr, keyPtr, keyArray.Length);
                    }
 

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
                    {
                        *((ushort*)b) = offset;

                        if (resultIsEncrypted)
                        {
                            var keyPtr = (ushort*)b;
                            keyPtr++;

                            *keyPtr = (ushort)key.Length;
                            keyPtr++;

                            //When encrypted, also write keys to idx
                            var ptr = (char*)keyPtr;
                            foreach (var character in key)
                            {
                                *ptr = character;
                                ptr++;
                            }

                            counter += sizeof(ushort) + keyArray.Length;
                        }
                    }

                    offset = (ushort)(offset + (sizeof(ushort) * 2) + keyArray.Length + encrypted.Length);
                    counter += sizeof(ushort);
                }

                var result = stream.ToArray();

                if (!resultIsEncrypted) return result;

                var originalOffsets = offsets;
                offsets = Encrypt(offsets, password, saltSize, iterations);
                originalOffsets.Clear();

                var encrypt = Encrypt(result, password);
                result.Clear();

                return encrypt;
            }
        }

        public static SecureString DecryptDictionary(byte[] input, string dictionaryKey, byte[] password, EncryptionOptions options = EncryptionOptions.Default, int iterations = DEFAULT_ITERATIONS, StringComparer comparer = null)
        {
            if (input.Length == 0)
            {
                var emptyString = new SecureString();
                emptyString.MakeReadOnly();

                return emptyString;
            }

            if (comparer == null)
                comparer = StringComparer.Ordinal;

            var src = input;

            var resultIsEncrypted = options.IsResultEncrypted();
            if (resultIsEncrypted)
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

        public static IDictionary<string, SecureString> DecryptDictionary(byte[] input, byte[] password, EncryptionOptions options = EncryptionOptions.Default, int iterations = DEFAULT_ITERATIONS)
        {
            var result = new Dictionary<string, SecureString>();

            if (input.Length == 0) return result;

            var src = input;
            if (options.IsResultEncrypted())
            {
                src = Decrypt(input, password, iterations);
                input.Clear();
            }

            var keysAreEncrypted = options.AreKeysEncrypted();

            fixed (byte* ptr = src)
            {
                var p = ptr;

                do
                {
                    var keyPtr = (ushort*)p;

                    var keySize = *keyPtr++;
                    var contentSize = *keyPtr++;

                    p = (byte*)keyPtr;

                    char[] key;
                    if (keysAreEncrypted)
                    {
                        var keyBytes = new byte[keySize];

                        fixed (void* k = keyBytes)
                            UnsafeNativeMethods.memcpy(k, p, keySize);

                        keyBytes = Decrypt(keyBytes, password, iterations);

                        key = new char[keyBytes.Length / sizeof(char)];

                        fixed (void* k = key, kb = keyBytes)
                            UnsafeNativeMethods.memcpy(k, kb, keyBytes.Length);

                        keyBytes.Clear();
                    }
                    else
                    {
                        key = new char[keySize / sizeof(char)];

                        fixed (void* k = key)
                            UnsafeNativeMethods.memcpy(k, p, keySize);
                    }
                    
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

        #endregion















        #region Simple Encryption

        public static byte[] EncryptSecureString(SecureString input, byte[] password, ushort saltSize = DEFAULT_SALTSIZE, int iterations = DEFAULT_ITERATIONS)
        {
            if (input.Length == 0) return new byte[0];

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
            if (length == 0) return new byte[0];

            var bytes = new byte[length * sizeof(char)];

            fixed (void* ptr = bytes)
                UnsafeNativeMethods.memcpy(ptr, input, bytes.Length);

            var result = Encrypt(bytes, password, saltSize, iterations);
            bytes.Clear();

            return result;
        }

        public static string DecryptString(byte[] input, byte[] password, int iterations = DEFAULT_ITERATIONS)
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

        public static byte[] Decrypt(byte[] input, byte[] password, int iterations = DEFAULT_ITERATIONS)
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
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [TargetedPatchingOptOut("Performance critical to inline across NGen image boundaries")]
        static void Clear<T>(this T[] bytes)
        {
            Array.Clear(bytes, 0, bytes.Length);
        }

        #endregion
    }
}