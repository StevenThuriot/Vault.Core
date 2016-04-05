using System.Security;
using Vault.Core.Extensions;

namespace Vault.Core
{
    static partial class ContainerFactory
    {
        public static IContainer<T> FromFile<T>(string file, Security<T> security) => new FileContainer<T>(file, security);
        public static IContainer<SecureString> FromFile(string file) => FromFile(file, new SecureStringSecurity());

        public static class WithSettings
        {
            public static ISettingsContainer<T> FromFile<T>(string file, Security<T> security, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS, bool clearPassword = true)
            {
                var container = new FileContainer<T>(file, security);
                var result = new SettingsContainer<T>(container, password, options, saltSize, iterations);

                if (clearPassword)
                    password.Clear();

                return result;
            }

            public static ISettingsContainer<SecureString> FromFile(string file, byte[] password, EncryptionOptions options = EncryptionOptions.Default, ushort saltSize = Defaults.SALTSIZE, int iterations = Defaults.ITERATIONS, bool clearPassword = true) => FromFile(file, new SecureStringSecurity(), password, options, saltSize, iterations, clearPassword);
        }
    }
}
