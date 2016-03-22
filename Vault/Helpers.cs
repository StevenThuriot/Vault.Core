using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Vault.Core
{
    static class Helpers
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
    }
}
