using System.Collections.Generic;

namespace Vault.Core
{
    partial interface ISettingsContainer<T> : IContainer<T>
    {
        void InsertOrUpdate(IDictionary<string, T> values);
        void InsertOrUpdate(string key, T value);
        void Encrypt(IDictionary<string, T> values);
        T Decrypt(string key);
        IDictionary<string, T> Decrypt();
    }
}
