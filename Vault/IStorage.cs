using System.IO;

namespace Vault.Core
{
    partial interface IStorage
    {
        bool Exists { get; }
        long Length { get; }
        bool IndexExists { get; }
        void WriteIndex(byte[] offsets);
        void Ensure();
        Stream Create();
        Stream Read();
        byte[] ResolveIndexes();
        EncryptionOptions ReadEncryptionOptions();
    }
}