using System;

namespace Vault
{
    [Flags]
    public enum EncryptionOptions : byte
    {
        None = 0,

        /// <summary>
        /// Still work in progress
        /// </summary>
        Keys   = 1 << 2,
        Result = 1 << 3,
        Offsets = 1 << 4,
        
        Default = Offsets
    }
}
