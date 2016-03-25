using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security;
using Vault.Core.Extensions;

namespace Vault.Core
{
    unsafe partial class Container : IContainer
    {
        readonly IStorage _storage;
        
        public Container(IStorage storage)
        {
            if (storage == null)
                throw new ArgumentNullException(nameof(storage));

            Contract.EndContractBlock();

            _storage = storage;
        }


        public void Merge(IDictionary<string, SecureString> values, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            var dictionary = Decrypt(password, iterations);
            var original = dictionary.Values.ToArray();

            foreach (var kvp in values)
                dictionary[kvp.Key] = kvp.Value;

            Encrypt(dictionary, password, options, saltSize, iterations);

            //Clean up decrypted keys, make user clean up their own.
            foreach (var secureString in original)
                secureString.Dispose();
        }

        public void Encrypt(IDictionary<string, SecureString> values, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            byte[] bytes;

            if (options.WriteOffsets())
            {
                byte[] offsets;
                bytes = Security.EncryptDictionary(values, password, out offsets, options, saltSize, iterations);

                _storage.WriteIndex(offsets);
                offsets.Clear();
            }
            else
            {
                bytes = Security.EncryptDictionary(values, password, options, saltSize, iterations);
            }

            using (var fs = _storage.Create())
            {
                fs.Write(new[] { (byte)options }, 0, 1);

                var writeStream = fs;

                var isZipped = options.IsZipped();
                if (isZipped) writeStream = new DeflateStream(fs, CompressionMode.Compress);

                try
                {
                    writeStream.Write(bytes, 0, bytes.Length);
                }
                finally
                {
                    if (isZipped) writeStream.Dispose();
                }
            }

            bytes.Clear();
        }

        public SecureString Decrypt(string key, byte[] password, int iterations)
        {
            _storage.Ensure();
            Contract.EndContractBlock();

            if (_storage.Length <= sizeof(EncryptionOptions)) //Empty file
                throw new KeyNotFoundException($"Key '{key}' was not found in the input array.");

            
            if (_storage.IndexExists)
            {
                return DecryptUsingIndexFile(key, password, iterations);
            }

            EncryptionOptions options;
            var bytes = ReadEncryptedFile(out options);

            var result = Security.DecryptDictionary(bytes, key, password, options, iterations);
            bytes.Clear();

            return result;
        }

        SecureString DecryptUsingIndexFile(string key, byte[] password, int iterations)
        {
            var indexes = _storage.ResolveIndexes();

            if (indexes.Length != 0)
            {
                var keyBytes = new byte[key.Length * sizeof(char)];

                fixed (void* keyPtr = key, destPtr = keyBytes)
                    UnsafeNativeMethods.memcpy(destPtr, keyPtr, keyBytes.Length);

                var options = _storage.ReadEncryptionOptions();
                
                if (options.IsResultEncrypted())
                {
                    indexes = Security.Decrypt(indexes, password, iterations);

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
                                    EncryptionOptions fileOptions;//unused
                                    var fileContent = ReadEncryptedFile(out fileOptions);

                                    var decryptedFile = Security.Decrypt(fileContent, password, iterations);

                                    fileContent.Clear();

                                    var valueLengthOffset = offset - sizeof(EncryptionOptions) + sizeof(ushort);
                                    var contentLength = decryptedFile[valueLengthOffset];
                                    var content = new byte[contentLength];

                                    fixed (byte* dest = content, src = decryptedFile)
                                    {
                                        var srcPtr = src + valueLengthOffset + sizeof(ushort) + keyLengthInBytes;
                                        UnsafeNativeMethods.memcpy(dest, srcPtr, content.Length);
                                    }

                                    var secureString = Security.DecryptSecureString(content, password, iterations);

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
                    using (var fs = _storage.Read())
                    {
                        var readStream = fs;

                        var isZipped = options.IsZipped();
                        if (isZipped)
                        {
                            fs.Seek(sizeof(EncryptionOptions), SeekOrigin.Begin);

                            readStream = new MemoryStream();
                            using (var zipStream = new DeflateStream(fs, CompressionMode.Decompress))
                            {
                                readStream.Write(new[] { (byte)options }, 0, sizeof(EncryptionOptions));
                                zipStream.CopyTo(readStream);
                                readStream.Position = 0;
                            }
                        }
                        try
                        {
                            fixed (byte* b = indexes)
                            {
                                var ptr = (ushort*)(b);

                                var length = new byte[sizeof(ushort)];
                                do
                                {
                                    readStream.Seek(*ptr, SeekOrigin.Begin);
                                    readStream.Read(length, 0, sizeof(ushort));

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

                                    readStream.Read(length, 0, length.Length); //contentLength
                                    readStream.Read(content, 0, content.Length); //key

                                    if (UnsafeNativeMethods.memcmp(content, keyBytes)) //check if keys match
                                    {
                                        fixed (byte* k = length)
                                            content = new byte[*(ushort*)k]; //content length

                                        readStream.Read(content, 0, content.Length);

                                        var secureString = Security.DecryptSecureString(content, password, iterations);

                                        content.Clear();

                                        return secureString;
                                    }

                                    ptr++;
                                } while (((byte*)ptr - b) != indexes.Length);
                            }
                        }
                        finally
                        {
                            if (isZipped) readStream.Dispose();
                        }
                    }
                }
            }

            throw new KeyNotFoundException($"Key '{key}' was not found in the input array.");
        }

        public IDictionary<string, SecureString> Decrypt(byte[] password, int iterations)
        {
            EncryptionOptions options;
            var bytes = ReadEncryptedFile(out options);

            var result = Security.DecryptDictionary(bytes, password, options, iterations);
            bytes.Clear();

            return result;
        }

        byte[] ReadEncryptedFile(out EncryptionOptions options)
        {
            _storage.Ensure();

            const int headerLength = sizeof(EncryptionOptions);

            if (_storage.Length <= headerLength) //Empty file
            {
                options = EncryptionOptions.None;
                return new byte[0];
            }

            byte[] bytes;

            using (var fs = _storage.Read())
            {
                int index = 0;
                int count = (int)fs.Length - headerLength;

                bytes = new byte[headerLength];

                fs.Read(bytes, 0, headerLength);

                fixed (byte* b = bytes)
                    options = *(EncryptionOptions*)b;
                
                if (options.IsZipped())
                {
                    using (var output = new MemoryStream())
                    using (var zipStream = new DeflateStream(fs, CompressionMode.Decompress))
                    {
                        zipStream.CopyTo(output);

                        output.Position = 0;
                        bytes = output.ToArray();
                    }
                }
                else
                {
                    bytes = new byte[count];

                    while (count > 0)
                    {
                        int n = fs.Read(bytes, index, count);

                        index += n;
                        count -= n;
                    }
                }
            }

            return bytes;
        }
    }
}