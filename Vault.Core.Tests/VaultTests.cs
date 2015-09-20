﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using Test;
using System.Security;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.IO;

namespace Vault.Core.Tests
{
    [TestClass]
    public class VaultTests
    {
        const string originalValue = "This is a sentence! :)";
        const string originalValue2 = "This is another sentence! :D";
        const string originalValue3 = "This is a third sentence~";

        static byte[] _value;
        static byte[] _password;

        [ClassInitialize]
        public static void InitVaultTests(TestContext context)
        {
            _value = Encoding.Unicode.GetBytes(originalValue);
            _password = Encoding.Unicode.GetBytes("This is a password!");
        }


        [TestMethod]
        public void CanEncrypt()
        {
            var result = Security.Encrypt(_value, _password);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
        }


        [TestMethod]
        public void CanEncryptAString()
        {
            var result = Security.EncryptString(originalValue, _password);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
        }

        [TestMethod]
        public unsafe void CanEncryptACharPointer()
        {
            var value = originalValue;
            fixed (char* inputPtr = value)
            {
                var result = Security.EncryptString(inputPtr, value.Length, _password);

                Assert.IsNotNull(result);
                Assert.IsTrue(result.Length != 0);
            }
        }

        [TestMethod]
        public unsafe void CanEncryptSecureString()
        {
            var value = originalValue.Secure();

            var result = Security.EncryptSecureString(value, _password);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
        }

        [TestMethod]
        public unsafe void CanEncryptDictionary()
        {
            var value = originalValue.Secure();

            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", value }
            };

            var result = Security.EncryptDictionary(dictionary, _password);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
        }

        [TestMethod]
        public unsafe void CanEncryptToAFile()
        {
            var value = originalValue.Secure();

            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", value }
            };


            var path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "CanEncryptToAFile.enc");
            File.Delete(path);

            Assert.IsFalse(File.Exists(path));

            Security.EncryptFile(dictionary, path, _password);

            var file = new FileInfo(path);
            Assert.IsTrue(file.Exists);
            Assert.AreNotEqual(0, file.Length);
        }

        [TestMethod]
        public unsafe void CanDecryptAFile()
        {
            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", originalValue.Secure() },
                { "another Key", originalValue2.Secure() }
            };


            var path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "CanEncryptToAFile.enc");
            File.Delete(path);

            Assert.IsFalse(File.Exists(path));

            Security.EncryptFile(dictionary, path, _password);

            var file = new FileInfo(path);
            Assert.IsTrue(file.Exists);
            Assert.AreNotEqual(0, file.Length);

            var decrypted = Security.DecryptFile(path, _password);

            Assert.IsNotNull(decrypted);
            Assert.AreEqual(dictionary.Count, decrypted.Count);
            for (int i = 0; i < dictionary.Count; i++)
            {
                var expected = dictionary.ElementAt(i);
                var actual = decrypted.ElementAt(i);

                Assert.AreEqual(expected.Key, actual.Key);
                Assert.AreEqual(expected.Value.Length, actual.Value.Length);
                Assert.AreEqual(expected.Value.ToUnsecureString(), actual.Value.ToUnsecureString());
            }
        }

        [TestMethod]
        public unsafe void CanMergeIntoAFile()
        {
            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", originalValue.Secure() },
                { "another key", originalValue2.Secure() }
            };

            var dictionary2 = new Dictionary<string, SecureString>
            {
                { "another key", originalValue3.Secure() },
            };

            var dictionary3 = new Dictionary<string, SecureString>
            {
                { "another third key", originalValue3.Secure() }
            };


            var path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "CanEncryptToAFile.enc");
            File.Delete(path);

            Assert.IsFalse(File.Exists(path));

            Security.EncryptFile(dictionary, path, _password);

            var file = new FileInfo(path);
            Assert.IsTrue(file.Exists);

            var firstLength = file.Length;
            Assert.AreNotEqual(0, firstLength);

            Security.MergeFile(dictionary2, path, _password);

            file.Refresh();
            Assert.AreNotEqual(0, file.Length);

            Security.MergeFile(dictionary3, path, _password);

            file.Refresh();
            Assert.AreNotEqual(0, file.Length);
            Assert.AreNotEqual(firstLength, file.Length);
            Assert.IsTrue(firstLength < file.Length);
        }

        [TestMethod]
        public void EncryptedValuesCanBeDecrypted()
        {
            var result = Security.Encrypt(_value, _password);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);

            result = Security.Decrypt(result, _password);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
            Assert.AreEqual(_value.Length, result.Length);
            CollectionAssert.AreEqual(_value, result);
        }

        [TestMethod]
        public void EncryptedValuesCanBeDecryptedAsString()
        {
            var result = Security.Encrypt(_value, _password);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);

            var stringResult = Security.DecryptString(result, _password);

            Assert.IsNotNull(stringResult);
            Assert.IsTrue(stringResult.Length != 0);
            Assert.AreEqual(originalValue, stringResult);
        }

        [TestMethod]
        public void EncryptedValuesCanBeDecryptedAsSecureString()
        {
            var result = Security.Encrypt(_value, _password);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);

            var stringResult = Security.DecryptSecureString(result, _password);

            Assert.IsNotNull(stringResult);
            Assert.IsTrue(stringResult.Length != 0);
            Assert.AreEqual(originalValue, stringResult.ToUnsecureString());
        }

        [TestMethod]
        public void EncryptedDictionaryCanBeDecrypted()
        {
            var value = originalValue.Secure();

            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", value }
            };

            var result = Security.EncryptDictionary(dictionary, _password);

            var decrypted = Security.DecryptDictionary(result, _password);

            Assert.IsNotNull(decrypted);
            Assert.AreEqual(dictionary.Count, decrypted.Count);
            for (int i = 0; i < dictionary.Count; i++)
            {
                var expected = dictionary.ElementAt(i);
                var actual = decrypted.ElementAt(i);

                Assert.AreEqual(expected.Key, actual.Key);
                Assert.AreEqual(expected.Value.Length, actual.Value.Length);
                Assert.AreEqual(expected.Value.ToUnsecureString(), actual.Value.ToUnsecureString());
            }
        }

        [TestMethod]
        public void SingleKeyCanBeDecryptedFromADictionary()
        {
            const string key = "another Key";
            var secureString = originalValue2.Secure();
            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", originalValue.Secure() },
                {  key, secureString }
            };

            var result = Security.EncryptDictionary(dictionary, _password);

            var decrypted = Security.DecryptDictionary(result, key, _password);

            Assert.IsNotNull(decrypted);
            Assert.AreEqual(secureString.Length, decrypted.Length);
            Assert.AreEqual(secureString.ToUnsecureString(), decrypted.ToUnsecureString());
        }

        [TestMethod]
        public void SingleKeyCanBeDecryptedFromAFile()
        {
            const string key = "another Key";
            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", originalValue.Secure() },
                { key, originalValue2.Secure() }
            };


            var path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "CanEncryptToAFile.enc");
            File.Delete(path);

            Assert.IsFalse(File.Exists(path));

            Security.EncryptFile(dictionary, path, _password);

            var file = new FileInfo(path);
            Assert.IsTrue(file.Exists);
            Assert.AreNotEqual(0, file.Length);

            var decrypted = Security.DecryptFile(path, key, _password);

            Assert.IsNotNull(decrypted);
            Assert.AreEqual(originalValue2.Length, decrypted.Length);
            Assert.AreEqual(originalValue2, decrypted.ToUnsecureString());
        }
    }
}
