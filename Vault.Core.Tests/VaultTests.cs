﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using Test;

namespace Vault.Core.Tests
{
    [TestClass]
    public class VaultTests
    {
        const string originalValue = "This is a sentence! :)";

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
    }
}
