using System.Collections.Generic;
using System.Security;

namespace Vault.Core
{
    partial interface IContainer
    {
        void Merge(IDictionary<string, SecureString> values, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        void Encrypt(IDictionary<string, SecureString> values, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS);
        SecureString Decrypt(string key, byte[] password, int iterations = Defaults.ITERATIONS);
        IDictionary<string, SecureString> Decrypt(byte[] password, int iterations = Defaults.ITERATIONS);
    }
}