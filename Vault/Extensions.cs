using System;
using System.Runtime;
using System.Runtime.CompilerServices;

namespace Vault.Core.Extensions
{
    static class Extensions
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
        public static bool IsZipped(this EncryptionOptions options) => (options & EncryptionOptions.Zip) == EncryptionOptions.Zip;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [TargetedPatchingOptOut("Performance critical to inline across NGen image boundaries")]
        public static bool AreKeysEncrypted(this EncryptionOptions options) => (options & EncryptionOptions.Keys) == EncryptionOptions.Keys;
        

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [TargetedPatchingOptOut("Performance critical to inline across NGen image boundaries")]
        public static void Clear<T>(this T[] bytes)
        {
            Array.Clear(bytes, 0, bytes.Length);
        }
    }
}
