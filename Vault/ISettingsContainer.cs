using System.Collections.Generic;

namespace Vault.Core
{
    partial interface ISettingsContainer<T> : IContainer<T>
    {
        void Insert(string key, T value);
        void Update(string key, T value);
        void Delete(string key);

        void Insert(IDictionary<string, T> values);
        void Update(IDictionary<string, T> values);
        void Delete(IEnumerable<string> keys);
        

        void InsertOrUpdate(IDictionary<string, T> values);
        void InsertOrUpdate(string key, T value);
        void Encrypt(IDictionary<string, T> values);
        T Decrypt(string key);
        IDictionary<string, T> Decrypt();
    }
}
