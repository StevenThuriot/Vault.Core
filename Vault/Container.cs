using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Vault.Core.Extensions;

namespace Vault.Core
{
    unsafe partial class Container<T> : IContainer<T>
    {
        readonly IStorage _storage;
        readonly Security<T> _security;

        public Container(IStorage storage, Security<T> security)
        {
            if (storage == null)
                throw Error.ArgumentNull(nameof(storage));
            if (security == null)
                throw Error.ArgumentNull(nameof(security));

            _storage = storage;
            _security = security;
        }


        public void Insert(string key, T value, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            if (ResolveKeys(password, iterations).Contains(key))
                throw Error.Argument(nameof(key), $"An element with the same key already exists ({key})");

            if (_storage.CanMerge)
            {
                //We can append!
                using (var fs = _storage.Append())
                {
                    if (_storage.HasOffsets)
                    {
                        var offset = (ushort)(fs.Length);

                        var indexes = _storage.ResolveIndexes();
                        var newIndexes = new byte[indexes.Length + sizeof(ushort)];
                        Array.Copy(indexes, newIndexes, indexes.Length);

                        fixed (byte* b = &newIndexes[indexes.Length])
                        {
                            *((ushort*)b) = offset;
                        }

                        _storage.WriteIndex(newIndexes);
                    }

                    var encrypted = _security.Encrypt(key, value, password, options, saltSize, iterations);
                    fs.Write(encrypted, 0, encrypted.Length);
                    encrypted.Clear();
                }
            }
            else
            {
                var dictionary = Decrypt(password, iterations);
                var original = dictionary.Values.ToArray();

                dictionary[key] = value;

                Encrypt(dictionary, password, options, saltSize, iterations);

                if (typeof(IDisposable).IsAssignableFrom(typeof(T)))
                {
                    //Clean up decrypted keys, make user clean up their own.
                    foreach (var disposable in original.OfType<IDisposable>())
                        disposable.Dispose();
                }
            }
        }

        public void Insert(IDictionary<string, T> values, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            var unsavedKeys = values.Keys.Intersect(ResolveKeys(password, iterations)).ToArray();

            if (unsavedKeys.Length != 0)
                throw Error.Argument($@"Elements with these keys already exist: 

{string.Join(Environment.NewLine, unsavedKeys)}");

            if (_storage.CanMerge)
            {
                //We can append!
                using (var fs = _storage.Append())
                {
                    var hasOffsets = _storage.HasOffsets;
                    byte[] newIndexes = null;
                    int oldIndexLength = 0;
                    ushort offset = 0;

                    if (hasOffsets)
                    {                        
                        var indexes = _storage.ResolveIndexes();
                        
                        oldIndexLength = indexes.Length;

                        newIndexes = new byte[oldIndexLength + (sizeof(ushort) * values.Count)];
                        Array.Copy(indexes, newIndexes, oldIndexLength);
                    }
                    
                    foreach (var kvp in values)
                    {
                        var key = kvp.Key;
                        var value = kvp.Value;

                        var encrypted = _security.Encrypt(key, value, password, options, saltSize, iterations);

                        offset = (ushort)(fs.Length);
                        fs.Write(encrypted, 0, encrypted.Length);

                        encrypted.Clear();

                        if (hasOffsets)
                        {
                            fixed (byte* b = &newIndexes[oldIndexLength])
                            {
                                *((ushort*)b) = offset;
                            }

                            oldIndexLength += sizeof(ushort);
                        }
                    }

                    if (hasOffsets)
                    {
                        _storage.WriteIndex(newIndexes);
                    }
                }
            }
            else
            {
                var dictionary = Decrypt(password, iterations);
                var original = dictionary.Values.ToArray();

                foreach (var kvp in values)
                {
                    dictionary[kvp.Key] = kvp.Value;
                }

                Encrypt(dictionary, password, options, saltSize, iterations);

                if (typeof(IDisposable).IsAssignableFrom(typeof(T)))
                {
                    //Clean up decrypted keys, make user clean up their own.
                    foreach (var disposable in original.OfType<IDisposable>())
                        disposable.Dispose();
                }
            }
        }

        public void Update(string key, T value, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            if (!ResolveKeys(password, iterations).Contains(key))
                throw Error.Argument(nameof(key), $"An element with that key does not exist ({key})");

            var dictionary = Decrypt(password, iterations);
            var original = dictionary.Values.ToArray();

            dictionary[key] = value;

            Encrypt(dictionary, password, options, saltSize, iterations);

            if (typeof(IDisposable).IsAssignableFrom(typeof(T)))
            {
                //Clean up decrypted keys, make user clean up their own.
                foreach (var disposable in original.OfType<IDisposable>())
                    disposable.Dispose();
            }
        }

        public void Update(IDictionary<string, T> values, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            var unsavedKeys = values.Keys.Except(ResolveKeys(password, iterations)).ToArray();

            if (unsavedKeys.Length != 0)
                throw Error.Argument($@"Elements with these keys does not exist: 

{string.Join(Environment.NewLine, unsavedKeys)}");

            var dictionary = Decrypt(password, iterations);
            var original = dictionary.Values.ToArray();

            foreach (var kvp in values)
            {
                dictionary[kvp.Key] = kvp.Value;
            }

            Encrypt(dictionary, password, options, saltSize, iterations);

            if (typeof(IDisposable).IsAssignableFrom(typeof(T)))
            {
                //Clean up decrypted keys, make user clean up their own.
                foreach (var disposable in original.OfType<IDisposable>())
                    disposable.Dispose();
            }
        }

        public void Delete(string key, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            if (!ResolveKeys(password, iterations).Contains(key))
                throw Error.Argument(nameof(key), $"An element with that key does not exist ({key})");

            var dictionary = Decrypt(password, iterations);
            var original = dictionary.Values.ToArray();

            dictionary.Remove(key);

            Encrypt(dictionary, password, options, saltSize, iterations);

            if (typeof(IDisposable).IsAssignableFrom(typeof(T)))
            {
                //Clean up decrypted keys, make user clean up their own.
                foreach (var disposable in original.OfType<IDisposable>())
                    disposable.Dispose();
            }
        }

        public void Delete(IEnumerable<string> keys, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            var unsavedKeys = keys.Except(ResolveKeys(password, iterations)).ToArray();

            if (unsavedKeys.Length != 0)
                throw Error.Argument($@"Elements with these keys does not exist: 

{string.Join(Environment.NewLine, unsavedKeys)}");

            var dictionary = Decrypt(password, iterations);
            var original = dictionary.Values.ToArray();

            foreach (var key in keys)
            {
                dictionary.Remove(key);
            }

            Encrypt(dictionary, password, options, saltSize, iterations);

            if (typeof(IDisposable).IsAssignableFrom(typeof(T)))
            {
                //Clean up decrypted keys, make user clean up their own.
                foreach (var disposable in original.OfType<IDisposable>())
                    disposable.Dispose();
            }
        }


        public void InsertOrUpdate(IDictionary<string, T> values, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            var dictionary = Decrypt(password, iterations);
            var original = dictionary.Values.ToArray();

            foreach (var kvp in values)
                dictionary[kvp.Key] = kvp.Value;

            Encrypt(dictionary, password, options, saltSize, iterations);


            if (typeof(IDisposable).IsAssignableFrom(typeof(T)))
            {
                //Clean up decrypted keys, make user clean up their own.
                foreach (var disposable in original.OfType<IDisposable>())
                    disposable.Dispose();
            }
        }

        public void InsertOrUpdate(string key, T value, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            var dictionary = Decrypt(password, iterations);

            dictionary[key] = value;

            Encrypt(dictionary, password, options, saltSize, iterations);

            if (typeof(IDisposable).IsAssignableFrom(typeof(T)))
            {
                //Clean up decrypted keys, make user clean up their own.
                foreach (var disposable in dictionary.OfType<IDisposable>())
                    disposable.Dispose();
            }
        }

        public void Encrypt(IDictionary<string, T> values, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            byte[] bytes;

            if (options.WriteOffsets())
            {
                byte[] offsets;
                bytes = _security.EncryptDictionary(values, password, out offsets, options, saltSize, iterations);

                _storage.WriteIndex(offsets);
                offsets.Clear();
            }
            else
            {
                bytes = _security.EncryptDictionary(values, password, options, saltSize, iterations);
            }

            using (var fs = _storage.Create(options))
            {
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

        public T Decrypt(string key, byte[] password, int iterations)
        {
            _storage.Ensure();

            if (_storage.Length <= sizeof(EncryptionOptions)) //Empty storage
                throw Error.KeyNotFound(key);

            if (_storage.HasOffsets)
            {
                return DecryptUsingOffsets(key, password, iterations);
            }

            EncryptionOptions options;
            var bytes = ReadEncryptedStorage(out options);

            var result = _security.DecryptDictionary(bytes, key, password, options, iterations);
            bytes.Clear();

            return result;
        }

        public IDictionary<string, T> Decrypt(byte[] password, int iterations)
        {
            EncryptionOptions options;
            var bytes = ReadEncryptedStorage(out options);

            var result = _security.DecryptDictionary(bytes, password, options, iterations);
            bytes.Clear();

            return result;
        }

        public IEnumerable<string> ResolveKeys(byte[] password, int iterations)
        {
            EncryptionOptions options;
            var bytes = ReadEncryptedStorage(out options);

            return _security.DecryptKeys(bytes, password, options, iterations);
        }









        
        T DecryptUsingOffsets(string key, byte[] password, int iterations)
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
                    return DecryptUsingOffsetsWithEncryptedResult(key, password, iterations, indexes, keyBytes, options);
                }

                return DecryptUsingOffsetsWithoutEncryptedResult(key, password, iterations, indexes, keyBytes, options);
            }

            throw Error.KeyNotFound(key);
        }

        T DecryptUsingOffsetsWithoutEncryptedResult(string key, byte[] password, int iterations, byte[] indexes, byte[] keyBytes, EncryptionOptions options)
        {
            var keysAreEncrypted = options.AreKeysEncrypted();

            using (var fs = _storage.Read())
            {
                var readStream = fs;

                var isZipped = options.IsZipped();
                if (isZipped)
                {
                    fs.Seek(sizeof(EncryptionOptions), SeekOrigin.Begin); //skip header

                    readStream = new MemoryStream();
                    using (var zipStream = new DeflateStream(fs, CompressionMode.Decompress))
                    {
                        var bytes = new byte[sizeof(EncryptionOptions)];

                        fixed (byte* b = bytes)
                            UnsafeNativeMethods.memcpy(b, &options, sizeof(EncryptionOptions));

                        readStream.Write(bytes, 0, sizeof(EncryptionOptions));
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
                            
                            if (!keysAreEncrypted)
                            {
                                fixed (byte* k = length)
                                {
                                    if (*(ushort*)k != keyBytes.Length)
                                    {
                                        ptr++;
                                        continue;
                                    }
                                }
                            }
                            
                            byte[] content;

                            fixed (byte* k = length)
                                content = new byte[*(ushort*)k];

                            readStream.Read(length, 0, length.Length); //contentLength
                            readStream.Read(content, 0, content.Length); //key

                            if (keysAreEncrypted)
                                content = Security.Decrypt(content, password, iterations);

                            var keysMatch = UnsafeNativeMethods.memcmp(content, keyBytes);

                            if (keysAreEncrypted)
                                content.Clear();

                            if (keysMatch)
                            {
                                fixed (byte* k = length)
                                    content = new byte[*(ushort*)k]; //content length

                                readStream.Read(content, 0, content.Length);

                                var decryptedValue = _security.DecryptValue(content, password, iterations);

                                content.Clear();

                                return decryptedValue;
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

            throw Error.KeyNotFound(key);
        }

        T DecryptUsingOffsetsWithEncryptedResult(string key, byte[] password, int iterations, byte[] indexes, byte[] keyBytes, EncryptionOptions options)
        {
            var keysAreEncrypted = options.AreKeysEncrypted();

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
                            //Key matches, read content from storage

                            //Since the entire storage has been encoded before saving, we need to read all the bytes and decode them first.
                            EncryptionOptions storageOptions;//unused
                            var storageContent = ReadEncryptedStorage(out storageOptions);

                            var decryptedStorage = Security.Decrypt(storageContent, password, iterations);

                            storageContent.Clear();

                            var valueLengthOffset = offset - sizeof(EncryptionOptions) + sizeof(ushort);

                            ushort contentLength;
                            fixed (byte* src = decryptedStorage)
                            {
                                var lengthPtr = src + valueLengthOffset;
                                contentLength = *(ushort*)lengthPtr;

                                if (keysAreEncrypted)
                                {
                                    keyLengthInBytes = *(ushort*)(lengthPtr - sizeof(ushort));
                                }
                            }

                            var content = new byte[contentLength];
                            
                            fixed (byte* dest = content, src = decryptedStorage)
                            {
                                var srcPtr = src + valueLengthOffset + sizeof(ushort) + keyLengthInBytes;
                                UnsafeNativeMethods.memcpy(dest, srcPtr, content.Length);
                            }

                            var decryptedValue = _security.DecryptValue(content, password, iterations);

                            content.Clear();

                            return decryptedValue;
                        }
                    }

                    keyArray.Clear();

                    var bytesPtr = (byte*)ptr;
                    bytesPtr += keyLengthInBytes;
                    ptr = (ushort*)bytesPtr;

                } while ((byte*)ptr - b != indexes.Length);
            }

            throw Error.KeyNotFound(key);
        }

        byte[] ReadEncryptedStorage(out EncryptionOptions options)
        {
            _storage.Ensure();

            const int headerLength = sizeof(EncryptionOptions);

            if (_storage.Length <= headerLength) //Empty storage
            {
                options = EncryptionOptions.None;
                return new byte[0];
            }
                        
            byte[] bytes;
            using (var fs = _storage.Read(out options))
            {
                int index = 0;
                int count = (int)fs.Length - headerLength;
                
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








        public void Insert(string key, T value, byte[] password, ushort saltSize, int iterations)
        {
            var options = _storage.ReadEncryptionOptions();
            Insert(key, value, password, options, saltSize, iterations);
        }

        public void Update(string key, T value, byte[] password, ushort saltSize, int iterations)
        {
            var options = _storage.ReadEncryptionOptions();
            Update(key, value, password, options, saltSize, iterations);
        }

        public void Delete(string key, byte[] password, ushort saltSize, int iterations)
        {
            var options = _storage.ReadEncryptionOptions();
            Delete(key, password, options, saltSize, iterations);
        }

        public void InsertOrUpdate(string key, T value, byte[] password, ushort saltSize, int iterations)
        {
            var options = _storage.ReadEncryptionOptions();
            InsertOrUpdate(key, value, password, options, saltSize, iterations);
        }

        public void Insert(IDictionary<string, T> values, byte[] password, ushort saltSize, int iterations)
        {
            var options = _storage.ReadEncryptionOptions();
            Insert(values, password, options, saltSize, iterations);
        }

        public void Update(IDictionary<string, T> values, byte[] password, ushort saltSize, int iterations)
        {
            var options = _storage.ReadEncryptionOptions();
            Update(values, password, options, saltSize, iterations);
        }

        public void Delete(IEnumerable<string> keys, byte[] password, ushort saltSize, int iterations)
        {
            var options = _storage.ReadEncryptionOptions();
            Delete(keys, password, options, saltSize, iterations);
        }

        public void InsertOrUpdate(IDictionary<string, T> values, byte[] password, ushort saltSize, int iterations)
        {
            var options = _storage.ReadEncryptionOptions();
            InsertOrUpdate(values, password, options, saltSize, iterations);
        }
    }
}