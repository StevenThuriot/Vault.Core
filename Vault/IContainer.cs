using System.Collections.Generic;
using System.Security;

namespace Vault.Core
{
    partial interface IContainer<T>
    {
        void InsertOrUpdate(IDictionary<string, T> values, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        void InsertOrUpdate(string key, T value, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        void Encrypt(IDictionary<string, T> values, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        T Decrypt(string key, byte[] password, int iterations = Defaults.ITERATIONS);
        IDictionary<string, T> Decrypt(byte[] password, int iterations = Defaults.ITERATIONS);
    }
}