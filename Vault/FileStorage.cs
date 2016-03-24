using System;
using System.Diagnostics.Contracts;
using System.IO;

namespace Vault.Core
{
    partial class FileStorage : IStorage
    {
        readonly string _file;
        readonly string _indexFile;

        public FileStorage(string file)
        {
            if (string.IsNullOrWhiteSpace(file))
                throw new ArgumentNullException(nameof(file));

            Contract.EndContractBlock();

            _file = file;
            _indexFile = Path.Combine(Path.GetDirectoryName(_file), Path.GetFileNameWithoutExtension(_file)) + ".idx";
        }

        public bool Exists => File.Exists(_file);
        public long Length => new FileInfo(_file).Length;
        public bool IndexExists => File.Exists(_indexFile);


        public void WriteIndex(byte[] offsets)
        {
            File.WriteAllBytes(_indexFile, offsets);
        }

        public void Ensure()
        {
            if (!Exists)
                throw new FileNotFoundException("File Not found", _file);
        }

        public Stream Create()
        {
            return new FileStream(_file, FileMode.Create);
        }

        public Stream Read()
        {
            return new FileStream(_file, FileMode.Open, FileAccess.Read, FileShare.Read);
        }

        public byte[] ResolveIndexes()
        {
            return File.ReadAllBytes(_indexFile);
        }
    }
}