using System.Security;

namespace Vault.Core
{
    static partial class ContainerFactory
    {
        public static IContainer<T> FromFile<T>(string file, Security<T> security) => new FileContainer<T>(file, security);
        public static IContainer<SecureString> FromFile(string file) => new FileContainer<SecureString>(file, new SecureStringSecurity());
    }
}
