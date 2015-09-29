using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using static System.Console;
using static Vault.Security;

namespace Test
{
    public static class Program
    {
        static void Main(string[] args)
        {
            var dict = new Dictionary<string, SecureString>();


            var ss1 = new SecureString();
            ss1.AppendChar('a');
            ss1.AppendChar('b');
            ss1.AppendChar('C');
            ss1.MakeReadOnly();
            var ss2 = new SecureString();
            ss2.AppendChar('d');
            ss2.AppendChar('E');
            ss2.AppendChar('f');
            ss2.MakeReadOnly();

            dict.Add("test   1", ss1);
            dict.Add("test 2", ss2);

            var pass = "test".Select(x => (byte)x).ToArray();

            const Vault.EncryptionOptions options = Vault.EncryptionOptions.Offsets | Vault.EncryptionOptions.Result;

            EncryptFile(dict, "test.vault", pass, options: options);

            var decrypted = DecryptFile("test.vault", "test 2", pass);

            var value = decrypted.ToUnsecureString();

            WriteLine(value);
        }

        public static string ToUnsecureString(this SecureString securePassword)
        {
            IntPtr unmanagedString = IntPtr.Zero;
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
