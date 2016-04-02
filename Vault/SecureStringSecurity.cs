using System;
using System.Runtime.InteropServices;
using System.Security;
using Vault.Core.Extensions;

namespace Vault.Core
{
    unsafe partial class SecureStringSecurity : Security<SecureString>
    {
        public override byte[] EncryptValue(SecureString input, byte[] password, ushort saltSize, int iterations)
        {
            if (input.Length == 0) return new byte[0];

            var ptr = IntPtr.Zero;
            byte[] bytes = null;

            try
            {
                ptr = Marshal.SecureStringToBSTR(input);
                bytes = new byte[input.Length * 2];

                fixed (void* b = bytes)
                    UnsafeNativeMethods.memcpy(b, ptr.ToPointer(), bytes.Length);

                return Security.Encrypt(bytes, password, saltSize, iterations);
            }
            finally
            {
                if (bytes != null)
                    bytes.Clear();

                if (ptr != IntPtr.Zero) Marshal.ZeroFreeBSTR(ptr);
            }
        }

        public override SecureString DecryptValue(byte[] input, byte[] password, int iterations)
        {
            var bytes = Security.Decrypt(input, password, iterations);

            SecureString value;

            fixed (byte* ptr = bytes)
                value = new SecureString((char*)ptr, bytes.Length / sizeof(char));

            value.MakeReadOnly();
            bytes.Clear();

            return value;
        }
    }
}
