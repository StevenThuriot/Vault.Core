using System;
using System.Diagnostics.Contracts;
using System.IO;
using Vault.Core.Extensions;

namespace Vault.Core
{
    partial class FileStorage : IStorage
    {
        readonly string _file;
        readonly string _indexFile;

        public FileStorage(string file)
        {
            if (string.IsNullOrWhiteSpace(file))
                throw Error.ArgumentNull(nameof(file));

            Contract.EndContractBlock();

            _file = file;
            _indexFile = Path.Combine(Path.GetDirectoryName(_file), Path.GetFileNameWithoutExtension(_file)) + ".idx";
        }

        public bool Exists => File.Exists(_file);
        public long Length => new FileInfo(_file).Length;
        public bool HasOffsets
        {
            get
            {
                if (!File.Exists(_indexFile))
                    return false;

                return ReadEncryptionOptions().WriteOffsets();
            }
        }

        public Stream Create() => new FileStream(_file, FileMode.Create);

        public Stream Read() => new FileStream(_file, FileMode.Open, FileAccess.Read, FileShare.Read);

        public byte[] ResolveIndexes() => File.ReadAllBytes(_indexFile);

        public void WriteIndex(byte[] offsets)
        {
            File.WriteAllBytes(_indexFile, offsets);
        }

        public void Ensure()
        {
            if (!Exists)
                throw Error.FileNotFound(_file);
        }

        public unsafe EncryptionOptions ReadEncryptionOptions()
        {
            if (Length <= sizeof(EncryptionOptions))
                return EncryptionOptions.None;

            byte[] bytes;
            using (var fs = Read())
            {
                bytes = new byte[sizeof(EncryptionOptions)];
                fs.Read(bytes, 0, sizeof(EncryptionOptions));
            }

            EncryptionOptions options;

            fixed (byte* b = bytes)
                options = *(EncryptionOptions*)b;

            return options;
        }

        public unsafe Stream Read(out EncryptionOptions options)
        {
            var fs = Read();
            
            var bytes = new byte[sizeof(EncryptionOptions)];

            fs.Read(bytes, 0, sizeof(EncryptionOptions));

            fixed (byte* b = bytes)
                options = *(EncryptionOptions*)b;

            return fs;
        }

        public unsafe Stream Create(EncryptionOptions options)
        {
            var fs = Create();

            var bytes = new byte[sizeof(EncryptionOptions)];

            fixed (byte* b = bytes)
                UnsafeNativeMethods.memcpy(b, &options, sizeof(EncryptionOptions));

            fs.Write(bytes, 0, sizeof(EncryptionOptions));

            return fs;
        }
    }
}