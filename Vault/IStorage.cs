using System.IO;

namespace Vault.Core
{
    partial interface IStorage
    {
        bool Exists { get; }
        long Length { get; }
        bool HasOffsets { get; }
        void WriteIndex(byte[] offsets);
        void Ensure();
        Stream Create();
        Stream Create(EncryptionOptions options);
        Stream Read();
        Stream Read(out EncryptionOptions options);
        byte[] ResolveIndexes();
        EncryptionOptions ReadEncryptionOptions();
    }
}