namespace Vault.Core
{
    public partial class ContainerFactory { }

    public partial interface IContainer<T> { }
    public partial class Container<T> { }
    public partial class FileContainer<T> { }

    public partial interface ISettingsContainer<T> { }
    public partial class SettingsContainer<T> { }

    public partial interface IStorage { }
    public partial class FileStorage { }

    public partial class Security { }
    public partial class Security<T> { }
    public partial class SecureStringSecurity { }
    public partial class Helpers { }
    public partial class Defaults { }

    
}

namespace Vault.Core.Extensions
{
    public static partial class Extensions { }
}

