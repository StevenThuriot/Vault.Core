using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.IO;
using System;
using System.Linq.Expressions;
using Vault.Core.Extensions;

namespace Vault.Core.Tests
{
    [TestClass]
    public class VaultTests
    {
        string _uniqueFilePath;

        public TestContext TestContext { get; set; }

        const string ORIGINAL_VALUE = "This is a sentence! :)";
        const string ORIGINAL_VALUE2 = "This is another sentence! :D";
        const string ORIGINAL_VALUE3 = "This is a third sentence~";

        static byte[] _value;
        static byte[] _password;
        static IEnumerable<EncryptionOptions> _testEncryptionOptions;

        static IEnumerable<EncryptionOptions> ResolveAllEncryptionOptionsCombinations()
        {
            var initalValues = (EncryptionOptions[])Enum.GetValues(typeof(EncryptionOptions));
            var discoveredCombinations = new HashSet<EncryptionOptions>(initalValues);
            var queue = new Queue<EncryptionOptions>(initalValues);
            
            while (queue.Count > 0)
            {
                var a = queue.Dequeue();
                foreach (var b in initalValues)
                {
                    var combo = a | b;
                    if (discoveredCombinations.Add(combo))
                        queue.Enqueue(combo);
                }
            }

            return discoveredCombinations;
        }


        [ClassInitialize]
#pragma warning disable RECS0154 // Parameter is never used
        public static void InitVaultTests(TestContext context)
#pragma warning restore RECS0154 // Parameter is never used
        {
            _value = Encoding.Unicode.GetBytes(ORIGINAL_VALUE);
            _password = Encoding.Unicode.GetBytes("This is a password!");

            _testEncryptionOptions = ResolveAllEncryptionOptionsCombinations();
        }

        [TestInitialize]
        public void TestInit()
        {
            _uniqueFilePath = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), TestContext.TestName + ".enc");
        }

        [TestCleanup]
        public void TestCleanup()
        {
            File.Delete(_uniqueFilePath);

            var idx = Path.Combine(Path.GetDirectoryName(_uniqueFilePath), Path.GetFileNameWithoutExtension(_uniqueFilePath)) + ".idx";
            File.Delete(idx);
        }

        void TestAllOptions(Action<EncryptionOptions, string> action, EncryptionOptions requiredFlagsForTest = EncryptionOptions.None)
        {
            TestAllOptions(action, options => (options & requiredFlagsForTest) == requiredFlagsForTest);
        }

        void TestAllOptions(Action<EncryptionOptions, string> action, Func<EncryptionOptions, bool> testFlag)
        {
            foreach (var options in _testEncryptionOptions)
            {
                if (!testFlag(options)) continue;

                var file = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), TestContext.TestName + "_" + options.ToString().Replace(", ", "_") + ".enc");

                action(options, file);

                File.Delete(file);
                var idx = Path.Combine(Path.GetDirectoryName(file), Path.GetFileNameWithoutExtension(file)) + ".idx";
                File.Delete(idx);
            }
        }

        [TestMethod]
        public void CanEncrypt()
        {
            var result = Security.Encrypt(_value, _password, Defaults.SALTSIZE, Defaults.ITERATIONS);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
        }


        [TestMethod]
        public void CanEncryptAString()
        {
            var result = Security.EncryptString(ORIGINAL_VALUE, _password, Defaults.SALTSIZE, Defaults.ITERATIONS);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
        }

        [TestMethod]
        public unsafe void CanEncryptACharPointer()
        {
            var value = ORIGINAL_VALUE;
            fixed (char* inputPtr = value)
            {
                var result = Security.EncryptString(inputPtr, value.Length, _password, Defaults.SALTSIZE, Defaults.ITERATIONS);

                Assert.IsNotNull(result);
                Assert.IsTrue(result.Length != 0);
            }
        }

        [TestMethod]
        public void CanEncryptSecureString()
        {
            var value = ORIGINAL_VALUE.Secure();

            var result = new SecureStringSecurity().EncryptValue(value, _password, Defaults.SALTSIZE, Defaults.ITERATIONS);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
        }

        [TestMethod]
        public void CanEncryptDictionary()
        {
            var value = ORIGINAL_VALUE.Secure();

            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", value }
            };

            var result = new SecureStringSecurity().EncryptDictionary(dictionary, _password, EncryptionOptions.Default, Defaults.SALTSIZE, Defaults.ITERATIONS);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
        }

        [TestMethod]
        public void CanEncryptDictionaryWithEncryptedKeys()
        {
            var value = ORIGINAL_VALUE.Secure();

            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", value }
            };

            var result = new SecureStringSecurity().EncryptDictionary(dictionary, _password, EncryptionOptions.Keys, Defaults.SALTSIZE, Defaults.ITERATIONS);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
        }

        [TestMethod]
        public void CanEncryptToAFile()
        {
            TestAllOptions((options, path) =>
            {
                var value = ORIGINAL_VALUE.Secure();

                var dictionary = new Dictionary<string, SecureString>
                {
                    {  "key", value }
                };
                
                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);

                Assert.IsTrue(file.Exists);
                Assert.AreNotEqual(0, file.Length);
            });
        }

        [TestMethod]
        public void CanDecryptAFile()
        {
            TestAllOptions((options, path) =>
            {
                var dictionary = new Dictionary<string, SecureString>
                {
                    {  "key", ORIGINAL_VALUE.Secure() },
                    { "another Key", ORIGINAL_VALUE2.Secure() }
                };
                
                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);
                Assert.AreNotEqual(0, file.Length);

                var decrypted = container.Decrypt(_password);

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
            });
        }

        [TestMethod]
        public void CanResolveKeys()
        {
            TestAllOptions((options, path) =>
            {
                var dictionary = new Dictionary<string, SecureString>
                {
                    {  "key", ORIGINAL_VALUE.Secure() },
                    { "another Key", ORIGINAL_VALUE2.Secure() }
                };
                
                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);
                Assert.AreNotEqual(0, file.Length);

                var decrypted = container.ResolveKeys(_password);

                Assert.IsNotNull(decrypted);
                Assert.AreEqual(dictionary.Count, decrypted.Count());

                for (int i = 0; i < dictionary.Count; i++)
                {
                    var expected = dictionary.ElementAt(i);
                    var actual = decrypted.ElementAt(i);

                    Assert.AreEqual(expected.Key, actual);
                }
            }, EncryptionOptions.Offsets);
        }
        
        [TestMethod]
        public void WorksWithTemporarilyStoredSettings()
        {
            TestAllOptions((options, path) =>
            {
                var dictionary = new Dictionary<string, SecureString>
                {
                    {  "key", ORIGINAL_VALUE.Secure() },
                    { "another Key", ORIGINAL_VALUE2.Secure() }
                };
                
                var container = ContainerFactory.WithSettings.FromFile(path, _password, options, clearPassword: false);
                container.Encrypt(dictionary);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);
                Assert.AreNotEqual(0, file.Length);

                var decrypted = container.Decrypt();

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
            });
        }


        [TestMethod]
        public void WontCrashOnEmptyFiles()
        {
            TestAllOptions((options, path) =>
            {
                File.WriteAllText(path, "");

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);
                Assert.AreEqual(0, file.Length);

                var container = ContainerFactory.FromFile(path);
                var decrypted = container.Decrypt(_password);

                Assert.IsNotNull(decrypted);
                Assert.AreEqual(0, decrypted.Count);
            });
        }

        [TestMethod, ExpectedException(typeof(KeyNotFoundException))]
        public void SingleKeyWillCrashOnEmptyFiles()
        {
            TestAllOptions((options, path) =>
            {
                File.WriteAllText(path, "");

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);
                Assert.AreEqual(0, file.Length);

                var container = ContainerFactory.FromFile(path);
                container.Decrypt("test", _password);
            });
        }

        [TestMethod]
        public void CanMergeIntoAFile()
        {
            TestAllOptions((options, path) =>
            {
                var dictionary = new Dictionary<string, SecureString>
                {
                    {  "key", ORIGINAL_VALUE.Secure() },
                    { "another key", ORIGINAL_VALUE2.Secure() }
                };

                var dictionary2 = new Dictionary<string, SecureString>
                {
                    { "another key", ORIGINAL_VALUE3.Secure() },
                };

                var dictionary3 = new Dictionary<string, SecureString>
                {
                    { "another third key", ORIGINAL_VALUE3.Secure() }
                };


                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options: options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);

                var firstLength = file.Length;
                Assert.AreNotEqual(0, firstLength);

                container.InsertOrUpdate(dictionary2, _password, options: options);

                file.Refresh();
                Assert.AreNotEqual(0, file.Length);

                container.InsertOrUpdate(dictionary3, _password, options: options);

                file.Refresh();
                Assert.AreNotEqual(0, file.Length);
                Assert.AreNotEqual(firstLength, file.Length);
                Assert.IsTrue(firstLength < file.Length);
            });
        }

        [TestMethod]
        public void CanInsertAKey()
        {
            TestAllOptions((options, path) =>
            {
                var dictionary = new Dictionary<string, SecureString>
                {
                    {  "key", ORIGINAL_VALUE.Secure() },
                    { "another key", ORIGINAL_VALUE2.Secure() }
                };
                
                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);

                var firstLength = file.Length;
                Assert.AreNotEqual(0, firstLength);

                const string insertedKey = "another third key";
                container.Insert(insertedKey, ORIGINAL_VALUE3.Secure(), _password, options);

                file.Refresh();
                Assert.AreNotEqual(0, file.Length);

                var decrypted = container.Decrypt(_password);

                Assert.AreEqual(3, decrypted.Count);
                foreach (var item in decrypted)
                {
                    SecureString value;
                    if (dictionary.TryGetValue(item.Key, out value))
                    {
                        Assert.AreEqual(value.ToUnsecureString(), item.Value.ToUnsecureString());
                        continue;
                    }

                    if (item.Key == insertedKey)
                    {
                        Assert.AreEqual(ORIGINAL_VALUE3, item.Value.ToUnsecureString());
                        continue;
                    }

                    Assert.Fail($"Key {item.Key} not found");
                }
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void CantInsertAKeyTwice()
        {
            TestAllOptions((options, path) =>
            {
                var dictionary = new Dictionary<string, SecureString>
                {
                    {  "key", ORIGINAL_VALUE.Secure() },
                    { "another key", ORIGINAL_VALUE2.Secure() }
                };
                
                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);

                var firstLength = file.Length;
                Assert.AreNotEqual(0, firstLength);

                container.Insert("another key", ORIGINAL_VALUE3.Secure(), _password);
                Assert.Fail("Should not be able to insert a key twice");

            });
        }

        [TestMethod]
        public void CanInsertSeveralKeys()
        {
            TestAllOptions((options, path) =>
            {
                var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { "another key", ORIGINAL_VALUE2.Secure() }
            };

                var dictionary2 = new Dictionary<string, SecureString>
            {
                { "another third key", ORIGINAL_VALUE3.Secure() },
                { "another fourth key", ORIGINAL_VALUE3.Secure() }
            };
                
                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);

                var firstLength = file.Length;
                Assert.AreNotEqual(0, firstLength);

                container.Insert(dictionary2, _password, options);

                file.Refresh();
                Assert.AreNotEqual(0, file.Length);

                var decrypted = container.Decrypt(_password);

                Assert.AreEqual(dictionary.Count + dictionary2.Count, decrypted.Count);
                foreach (var item in decrypted)
                {
                    SecureString value;
                    if (dictionary.TryGetValue(item.Key, out value) || dictionary2.TryGetValue(item.Key, out value))
                    {
                        Assert.AreEqual(value.ToUnsecureString(), item.Value.ToUnsecureString());
                        continue;
                    }

                    Assert.Fail($"Key {item.Key} not found");
                }
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void CantInsertSeveralKeysTwice()
        {
            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { "another key", ORIGINAL_VALUE2.Secure() }
            };

            var dictionary2 = new Dictionary<string, SecureString>
            {
                { "another third key", ORIGINAL_VALUE3.Secure() },
                { "another key", ORIGINAL_VALUE3.Secure() }
            };

            var path = _uniqueFilePath;

            Assert.IsFalse(File.Exists(path));

            var container = ContainerFactory.FromFile(path);
            container.Encrypt(dictionary, _password);

            var file = new FileInfo(path);
            Assert.IsTrue(file.Exists);

            var firstLength = file.Length;
            Assert.AreNotEqual(0, firstLength);

            container.Insert(dictionary2, _password);
            Assert.Fail("Should not be able to insert a key twice");
        }



        [TestMethod]
        public void CanUpdateAKey()
        {
            TestAllOptions((options, path) =>
            {
                const string UpdateedKey = "another key";
                var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { UpdateedKey, ORIGINAL_VALUE2.Secure() }
            };
                
                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);

                var firstLength = file.Length;
                Assert.AreNotEqual(0, firstLength);

                container.Update(UpdateedKey, ORIGINAL_VALUE3.Secure(), _password, options);

                file.Refresh();
                Assert.AreNotEqual(0, file.Length);

                var decrypted = container.Decrypt(_password);

                Assert.AreEqual(2, decrypted.Count);
                foreach (var item in decrypted)
                {
                    if (item.Key == UpdateedKey)
                    {
                        Assert.AreEqual(ORIGINAL_VALUE3, item.Value.ToUnsecureString());
                        continue;
                    }

                    SecureString value;
                    if (dictionary.TryGetValue(item.Key, out value))
                    {
                        Assert.AreEqual(value.ToUnsecureString(), item.Value.ToUnsecureString());
                        continue;
                    }

                    Assert.Fail($"Key {item.Key} not found");
                }
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void CantUpdateAKeyThatDoesntExist()
        {
            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { "another key", ORIGINAL_VALUE2.Secure() }
            };

            var path = _uniqueFilePath;

            Assert.IsFalse(File.Exists(path));

            var container = ContainerFactory.FromFile(path);
            container.Encrypt(dictionary, _password);

            var file = new FileInfo(path);
            Assert.IsTrue(file.Exists);

            var firstLength = file.Length;
            Assert.AreNotEqual(0, firstLength);

            container.Update("another unexisting key", ORIGINAL_VALUE3.Secure(), _password);
            Assert.Fail("Should not be able to Update a key that doesn't exist");
        }

        [TestMethod]
        public void CanUpdateSeveralKeys()
        {
            TestAllOptions((options, path) =>
            {
                var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { "another key", ORIGINAL_VALUE2.Secure() }
            };

                var dictionary2 = new Dictionary<string, SecureString>
            {
                { "another key", ORIGINAL_VALUE3.Secure() },
                { "key", ORIGINAL_VALUE3.Secure() }
            };

                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);

                var firstLength = file.Length;
                Assert.AreNotEqual(0, firstLength);

                container.Update(dictionary2, _password, options);

                file.Refresh();
                Assert.AreNotEqual(0, file.Length);

                var decrypted = container.Decrypt(_password);

                Assert.AreEqual(2, decrypted.Count);
                foreach (var item in decrypted)
                {
                    SecureString value;
                    if (dictionary2.TryGetValue(item.Key, out value) || dictionary.TryGetValue(item.Key, out value))
                    {
                        Assert.AreEqual(value.ToUnsecureString(), item.Value.ToUnsecureString());
                        continue;
                    }

                    Assert.Fail($"Key {item.Key} not found");
                }
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void CantUpdateSeveralKeysThatDontExist()
        {
            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { "another key", ORIGINAL_VALUE2.Secure() }
            };

            var dictionary2 = new Dictionary<string, SecureString>
            {
                { "another third key", ORIGINAL_VALUE3.Secure() },
                { "another key", ORIGINAL_VALUE3.Secure() }
            };

            var path = _uniqueFilePath;

            Assert.IsFalse(File.Exists(path));

            var container = ContainerFactory.FromFile(path);
            container.Encrypt(dictionary, _password);

            var file = new FileInfo(path);
            Assert.IsTrue(file.Exists);

            var firstLength = file.Length;
            Assert.AreNotEqual(0, firstLength);

            container.Update(dictionary2, _password);
            Assert.Fail("Should not be able to Update a key that doesn't exist");
        }

        [TestMethod]
        public void CanDeleteAKey()
        {
            TestAllOptions((options, path) =>
            {
                const string deleteKey = "another key";
                var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { deleteKey, ORIGINAL_VALUE2.Secure() }
            };
                
                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);

                var firstLength = file.Length;
                Assert.AreNotEqual(0, firstLength);

                container.Delete(deleteKey, _password, options);

                file.Refresh();
                Assert.AreNotEqual(0, file.Length);

                var decrypted = container.Decrypt(_password);

                Assert.AreEqual(1, decrypted.Count);
                foreach (var item in decrypted)
                {
                    SecureString value;
                    if (dictionary.TryGetValue(item.Key, out value))
                    {
                        Assert.AreEqual(value.ToUnsecureString(), item.Value.ToUnsecureString());
                        continue;
                    }

                    Assert.Fail($"Key {item.Key} not found");
                }
            });
        }


        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void CantDeleteAKeyThatDoesntExist()
        {
            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { "another key", ORIGINAL_VALUE2.Secure() }
            };

            var path = _uniqueFilePath;

            Assert.IsFalse(File.Exists(path));

            var container = ContainerFactory.FromFile(path);
            container.Encrypt(dictionary, _password);

            var file = new FileInfo(path);
            Assert.IsTrue(file.Exists);

            var firstLength = file.Length;
            Assert.AreNotEqual(0, firstLength);

            container.Update("another unexisting key", ORIGINAL_VALUE3.Secure(), _password);
            Assert.Fail("Should not be able to delete a key that doesn't exist");
        }

        [TestMethod]
        public void CanDeleteSeveralKeys()
        {
            TestAllOptions((options, path) =>
            {
                const string deleteKey = "another key";
                var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { deleteKey + "1", ORIGINAL_VALUE2.Secure() },
                { deleteKey + "2", ORIGINAL_VALUE2.Secure() }
            };
                
                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);

                var firstLength = file.Length;
                Assert.AreNotEqual(0, firstLength);

                container.Delete(new[] { deleteKey + "1", deleteKey + "2" }, _password, options);

                file.Refresh();
                Assert.AreNotEqual(0, file.Length);

                var decrypted = container.Decrypt(_password);

                Assert.AreEqual(1, decrypted.Count);
                foreach (var item in decrypted)
                {
                    SecureString value;
                    if (dictionary.TryGetValue(item.Key, out value))
                    {
                        Assert.AreEqual(value.ToUnsecureString(), item.Value.ToUnsecureString());
                        continue;
                    }

                    Assert.Fail($"Key {item.Key} not found");
                }
            });
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void CantDeleteSeveralKeysThatDontExist()
        {
            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { "another key", ORIGINAL_VALUE2.Secure() }
            };

            var path = _uniqueFilePath;

            Assert.IsFalse(File.Exists(path));

            var container = ContainerFactory.FromFile(path);
            container.Encrypt(dictionary, _password);

            var file = new FileInfo(path);
            Assert.IsTrue(file.Exists);

            var firstLength = file.Length;
            Assert.AreNotEqual(0, firstLength);

            container.Delete(new[] { "another third key", "another key" }, _password);
            Assert.Fail("Should not be able to Update a key that doesn't exist");
        }


        [TestMethod]
        public void CanMergeIntoAnEmptyFile()
        {
            TestAllOptions((options, path) =>
            {
                File.WriteAllText(path, "");

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);
                Assert.AreEqual(0, file.Length);

                var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { "another key", ORIGINAL_VALUE2.Secure() }
            };

                var container = ContainerFactory.FromFile(path);
                container.InsertOrUpdate(dictionary, _password, options);

                file.Refresh();
                Assert.AreNotEqual(0, file.Length);
            });
        }

        [TestMethod, ExpectedException(typeof(FileNotFoundException))]
        public void CannotMergeIntoAFileThatDoesntExist()
        {
            var path = _uniqueFilePath;

            Assert.IsFalse(File.Exists(path));

            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { "another key", ORIGINAL_VALUE2.Secure() }
            };

            var container = ContainerFactory.FromFile(path);
            container.InsertOrUpdate(dictionary, _password);

            Assert.Fail("Should have thrown a FileNotFoundException");
        }

        [TestMethod, ExpectedException(typeof(FileNotFoundException))]
        public void CannotDecryptAFileThatDoesntExist()
        {
            var path = _uniqueFilePath;

            Assert.IsFalse(File.Exists(path));

            var container = ContainerFactory.FromFile(path);
            container.Decrypt(_password);

            Assert.Fail("Should have thrown a FileNotFoundException");
        }

        [TestMethod]
        public void EncryptedValuesCanBeDecrypted()
        {
            var result = Security.Encrypt(_value, _password, Defaults.SALTSIZE, Defaults.ITERATIONS);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);

            result = Security.Decrypt(result, _password, Defaults.ITERATIONS);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);
            Assert.AreEqual(_value.Length, result.Length);
            CollectionAssert.AreEqual(_value, result);
        }

        [TestMethod]
        public void EncryptedValuesCanBeDecryptedAsString()
        {
            var result = Security.Encrypt(_value, _password, Defaults.SALTSIZE, Defaults.ITERATIONS);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);

            var stringResult = Security.DecryptString(result, _password, Defaults.ITERATIONS);

            Assert.IsNotNull(stringResult);
            Assert.IsTrue(stringResult.Length != 0);
            Assert.AreEqual(ORIGINAL_VALUE, stringResult);
        }

        [TestMethod]
        public void EncryptedValuesCanBeDecryptedAsSecureString()
        {
            var result = Security.Encrypt(_value, _password, Defaults.SALTSIZE, Defaults.ITERATIONS);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length != 0);


            var stringResult = new SecureStringSecurity().DecryptValue(result, _password, Defaults.ITERATIONS);

            Assert.IsNotNull(stringResult);
            Assert.IsTrue(stringResult.Length != 0);
            Assert.AreEqual(ORIGINAL_VALUE, stringResult.ToUnsecureString());
        }

        [TestMethod]
        public void EncryptedDictionaryCanBeDecrypted()
        {
            TestAllOptions((options, path) =>
            {
                var value = ORIGINAL_VALUE.Secure();

                var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", value }
            };

                var security = new SecureStringSecurity();
                var result = security.EncryptDictionary(dictionary, _password, options, Defaults.SALTSIZE, Defaults.ITERATIONS);

                var decrypted = security.DecryptDictionary(result, _password, options, Defaults.ITERATIONS);

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
            });
        }

        [TestMethod]
        public void SingleKeyCanBeDecryptedFromADictionary()
        {
            TestAllOptions((options, path) =>
            {
                const string key = "another Key";
                var secureString = ORIGINAL_VALUE2.Secure();
                var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                {  key, secureString }
            };

                var security = new SecureStringSecurity();
                var result = security.EncryptDictionary(dictionary, _password, options, Defaults.SALTSIZE, Defaults.ITERATIONS);

                var decrypted = security.DecryptDictionary(result, key, _password, options, Defaults.ITERATIONS);

                Assert.IsNotNull(decrypted);
                Assert.AreEqual(secureString.Length, decrypted.Length);
                Assert.AreEqual(secureString.ToUnsecureString(), decrypted.ToUnsecureString());
            });
        }

        [TestMethod]
        public void SingleKeyCanBeDecryptedFromAFile()
        {
            TestAllOptions((options, path) =>
            {
                const string key = "another Key";
                var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", ORIGINAL_VALUE.Secure() },
                { key, ORIGINAL_VALUE2.Secure() }
            };

                
                var container = ContainerFactory.FromFile(path);
                container.Encrypt(dictionary, _password, options);

                var file = new FileInfo(path);
                Assert.IsTrue(file.Exists);
                Assert.AreNotEqual(0, file.Length);

                var decrypted = container.Decrypt(key, _password);

                Assert.IsNotNull(decrypted);
                Assert.AreEqual(ORIGINAL_VALUE2.Length, decrypted.Length);
                Assert.AreEqual(ORIGINAL_VALUE2, decrypted.ToUnsecureString());
            });
        }
        
        [TestMethod, ExpectedException(typeof(System.Security.Cryptography.CryptographicException))]
        public void DecryptingWithAWrongPasswordThrowsAnException()
        {
            var value = ORIGINAL_VALUE.Secure();

            var dictionary = new Dictionary<string, SecureString>
            {
                {  "key", value }
            };


            var path = _uniqueFilePath;

            Assert.IsFalse(File.Exists(path));

            var container = ContainerFactory.FromFile(path);
            container.Encrypt(dictionary, _password);

            var file = new FileInfo(path);
            Assert.IsTrue(file.Exists);
            Assert.AreNotEqual(0, file.Length);

            container.Decrypt(Encoding.Unicode.GetBytes("This password is wrong"));
        }
    }
}
