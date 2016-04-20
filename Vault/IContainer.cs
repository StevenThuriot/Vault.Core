using System.Collections.Generic;

namespace Vault.Core
{
    partial interface IContainer<T>
    {
        void Insert(string key, T value, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        void Update(string key, T value, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        void Delete(string key, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);

        void Insert(IDictionary<string, T> values, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        void Update(IDictionary<string, T> values, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        void Delete(IEnumerable<string> keys, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);


        void InsertOrUpdate(IDictionary<string, T> values, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        void InsertOrUpdate(string key, T value, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        void Encrypt(IDictionary<string, T> values, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        T Decrypt(string key, byte[] password, int iterations = Defaults.ITERATIONS);
        IDictionary<string, T> Decrypt(byte[] password, int iterations = Defaults.ITERATIONS);
        IEnumerable<string> ResolveKeys(byte[] password, int iterations = Defaults.ITERATIONS);
    }
}