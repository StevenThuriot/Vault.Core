using System;
using System.Collections.Generic;
using System.IO;

namespace Vault
{
    static class Error
    {
        public static Exception KeyNotFound(string key) => new KeyNotFoundException($"Key '{key}' was not found in the input array.");
        public static Exception ArgumentNull(string name) => new ArgumentNullException(name, $"'{name}' can not be NULL");
        public static Exception Argument(string name, string message) => new ArgumentException(message, name);
        public static Exception Argument(string message) => new ArgumentException(message);
        public static Exception FileNotFound(string file) => new FileNotFoundException($"File '{file}' was not found.", file);
    }
}
