﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Vault.Core.Extensions;

namespace Vault.Core
{

    unsafe abstract partial class Security<T>
    {
        #region Key Value Encryption

        public byte[] EncryptDictionary(IDictionary<string, T> values, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            byte[] offsets;
            var result = EncryptDictionary(values, password, out offsets, options, saltSize, iterations);

            offsets.Clear();

            return result;
        }

        public byte[] EncryptDictionary(IDictionary<string, T> values, byte[] password, out byte[] offsets, EncryptionOptions options, ushort saltSize, int iterations)
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
                var offset = (ushort)sizeof(EncryptionOptions);

                var keysShouldBeEncrypted = options.AreKeysEncrypted();

                foreach (var kvp in values)
                {
                    var key = kvp.Key;

                    byte[] keyArray;
                    if (keysShouldBeEncrypted)
                    {
                        keyArray = Security.EncryptString(key, password, saltSize, iterations);
                    }
                    else
                    {
                        keyArray = new byte[key.Length * sizeof(char)];

                        fixed (void* keyPtr = key, destPtr = keyArray)
                            UnsafeNativeMethods.memcpy(destPtr, keyPtr, keyArray.Length);
                    }


                    var encrypted = EncryptValue(kvp.Value, password, saltSize, iterations);

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
                offsets = Security.Encrypt(offsets, password, saltSize, iterations);
                originalOffsets.Clear();

                var encrypt = Security.Encrypt(result, password, saltSize, iterations);
                result.Clear();

                return encrypt;
            }
        }

        public T DecryptDictionary(byte[] input, string dictionaryKey, byte[] password, EncryptionOptions options, int iterations, StringComparer comparer = null)
        {
            if (input.Length == 0)
            {
                return default(T);
            }

            if (comparer == null)
                comparer = StringComparer.Ordinal;

            var src = input;

            var resultIsEncrypted = options.IsResultEncrypted();
            if (resultIsEncrypted)
            {
                src = Security.Decrypt(input, password, iterations);
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
                            var T = DecryptValue(content, password, iterations);

                            content.Clear();

                            return T;
                        }
                    }

                    p += contentSize;


                } while (p - ptr != input.Length);
            }

            throw new KeyNotFoundException($"Key '{dictionaryKey}' was not found in the input array.");
        }

        public IDictionary<string, T> DecryptDictionary(byte[] input, byte[] password, EncryptionOptions options, int iterations)
        {
            var result = new Dictionary<string, T>();

            if (input.Length == 0) return result;

            var src = input;
            if (options.IsResultEncrypted())
            {
                src = Security.Decrypt(input, password, iterations);
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

                        keyBytes = Security.Decrypt(keyBytes, password, iterations);

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

                        result[new string(key)] = DecryptValue(content, password, iterations);

                        key.Clear();
                        content.Clear();
                    }

                    p += contentSize;

                } while ((p - ptr) != src.Length);
            }

            return result;
        }

        public IEnumerable<string> DecryptKeys(byte[] input, byte[] password, EncryptionOptions options, int iterations)
        {
            if (input.Length == 0)
                return Enumerable.Empty<string>();

            var keys = new List<string>();

            var src = input;
            if (options.IsResultEncrypted())
            {
                src = Security.Decrypt(input, password, iterations);
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

                        keyBytes = Security.Decrypt(keyBytes, password, iterations);

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
                    
                    keys.Add(new string(key));
                    key.Clear();

                    p += contentSize;

                } while ((p - ptr) != src.Length);
            }

            return keys;
        }

        public abstract byte[] EncryptValue(T input, byte[] password, ushort saltSize, int iterations);

        public abstract T DecryptValue(byte[] input, byte[] password, int iterations);

        #endregion
    }
}