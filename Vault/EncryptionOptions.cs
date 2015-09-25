﻿using System;
using System.Runtime;
using System.Runtime.CompilerServices;

namespace Vault
{
    [Flags]
    public enum EncryptionOptions
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

    static class EncryptionCheck
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [TargetedPatchingOptOut("Performance critical to inline across NGen image boundaries")]
        public static bool HasFlag(this EncryptionOptions options, EncryptionOptions option) => (options & option) == option;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [TargetedPatchingOptOut("Performance critical to inline across NGen image boundaries")]
        public static bool WriteOffsets(this EncryptionOptions options) => (options & EncryptionOptions.Offsets) == EncryptionOptions.Offsets;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [TargetedPatchingOptOut("Performance critical to inline across NGen image boundaries")]
        public static bool IsResultEncrypted(this EncryptionOptions options) => (options & EncryptionOptions.Result) == EncryptionOptions.Result;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [TargetedPatchingOptOut("Performance critical to inline across NGen image boundaries")]
        public static bool AreKeysEncrypted(this EncryptionOptions options) => (options & EncryptionOptions.Keys) == EncryptionOptions.Keys;
    }
}
