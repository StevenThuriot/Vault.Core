using System;

namespace Vault.Core
{
    [Flags]
    public enum EncryptionOptions : byte
    {
        None = 0,
        
        Keys   = 1 << 2,
        Result = 1 << 3,
        Offsets = 1 << 4,
        Zip = 1 << 5,

        Default = Offsets
    }
}
