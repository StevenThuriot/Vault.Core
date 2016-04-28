using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Vault.Core
{
    static partial class Helpers
    {
        public static string ToUnsecureString(this SecureString securePassword)
        {
            var unmanagedString = IntPtr.Zero;

            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
                return Marshal.PtrToStringUni(unmanagedString);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

        public static unsafe SecureString Secure(this string value)
        {
            fixed (char* v = value)
                return new SecureString(v, value.Length);
        }






        public static IDisposable Scoped<T>(this T[] bytes) => new ScopeHelper<T>(bytes);

        class ScopeHelper<T> : IDisposable
        {
            T[] _bytes;

            public ScopeHelper(T[] bytes)
            {
                _bytes = bytes;
            }

            public void Dispose()
            {
                Array.Clear(_bytes, 0, _bytes.Length);
                _bytes = null;
            }
        }
    }
}
