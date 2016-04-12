using System;
using System.Collections.Generic;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using Vault.Core.Extensions;

namespace Vault.Core
{
    unsafe partial class SettingsContainer<T> : ISettingsContainer<T>
    {
        readonly IContainer<T> _container;
        readonly SecureString _password;
        readonly EncryptionOptions _options;
        readonly ushort _saltSize;
        readonly int _iterations;

        public SettingsContainer(IContainer<T> container, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            _container = container;
            _options = options;
            _saltSize = saltSize;
            _iterations = iterations;
            
            //Secure password in memory
            fixed (byte* ptr = password)
                _password = new SecureString((char*)ptr, password.Length / sizeof(char));
        }

        byte[] ResolvePassword()
        {
            byte[] bytes;
            var ptr = Marshal.SecureStringToBSTR(_password);
            bytes = new byte[_password.Length * 2];

            fixed (void* b = bytes)
                UnsafeNativeMethods.memcpy(b, ptr.ToPointer(), bytes.Length);

            return bytes;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [TargetedPatchingOptOut("Performance critical to inline across NGen image boundaries")]
        TResult Run<TResult>(Func<byte[], TResult> resolve)
        {
            byte[] bytes = null;

            try
            {
                bytes = ResolvePassword();
                return resolve(bytes);
            }
            finally
            {
                if (bytes != null)
                    bytes.Clear();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [TargetedPatchingOptOut("Performance critical to inline across NGen image boundaries")]
        void Run(Action<byte[]> resolve)
        {
            byte[] bytes = null;

            try
            {
                bytes = ResolvePassword();
                resolve(bytes);
            }
            finally
            {
                if (bytes != null)
                    bytes.Clear();
            }
        }


        public IDictionary<string, T> Decrypt()
        {
            return Run(pass => _container.Decrypt(pass, _iterations));
        }

        public T Decrypt(string key)
        {
            return Run(pass => _container.Decrypt(key, pass, _iterations));
        }

        public void Encrypt(IDictionary<string, T> values)
        {
            Run(pass => _container.Encrypt(values, pass, _options, _saltSize, _iterations));
        }

        public void InsertOrUpdate(IDictionary<string, T> values)
        {
            Run(pass => _container.InsertOrUpdate(values, pass, _options, _saltSize, _iterations));
        }

        public void InsertOrUpdate(string key, T value)
        {
            Run(pass => _container.InsertOrUpdate(key, value, pass, _options, _saltSize, _iterations));
        }









        public void InsertOrUpdate(IDictionary<string, T> values, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            _container.InsertOrUpdate(values, password, options, saltSize, iterations);
        }

        public void InsertOrUpdate(string key, T value, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            _container.InsertOrUpdate(key, value, password, options, saltSize, iterations);
        }

        public void Encrypt(IDictionary<string, T> values, byte[] password, EncryptionOptions options, ushort saltSize, int iterations)
        {
            _container.Encrypt(values, password, options, saltSize, iterations);
        }

        public T Decrypt(string key, byte[] password, int iterations)
        {
            return _container.Decrypt(key, password, iterations);
        }

        public IDictionary<string, T> Decrypt(byte[] password, int iterations)
        {
            return _container.Decrypt(password, iterations);
        }

        public IEnumerable<string> ResolveKeys(byte[] password, int iterations)
        {
            return _container.ResolveKeys(password, iterations);
        }
    }
}
