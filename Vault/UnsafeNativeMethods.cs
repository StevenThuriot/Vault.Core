using System;
using System.Runtime.InteropServices;

namespace Vault.Core
{
    static unsafe class UnsafeNativeMethods
    {
        [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public static extern IntPtr memcpy(void* dest, void* src, int count);

        [DllImport("msvcrt.dll", EntryPoint = "memset", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public static extern IntPtr memset(void* dest, int c, int count);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int memcmp(byte[] b1, byte[] b2, long count);

        public static bool memcmp(byte[] b1, byte[] b2) => b1.Length == b2.Length && memcmp(b1, b2, b1.Length) == 0;
    }
}
