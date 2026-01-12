using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
public class EncryptionService
{  
    public class CryptoIdentityService
    {
        public class KeyPair
        {
            public byte[] PublicKey { get; set; } = new byte[32];
            public byte[] PrivateKey { get; set; } = new byte[64];

            public byte[] EncryptionPrivateKey { get; set; } = new byte[32];
            public byte[] EncryptionPublicKey { get; set; } = new byte[32];

            public string MnemonicPhrase { get; set; }
            public DateTime GenerateAt { get; set; } = DateTime.UtcNow;

            public string PublicKeyBase64 => Convert.ToBase64String(PublicKey);
            public string EncryptionPublicKeyBase64 => Convert.ToBase64String(EncryptionPublicKey);
        }
        
        public static KeyPair GenerateNewKeyPair()
        {
            byte[] ed25519Seed = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(ed25519Seed);
            }

            Chaos.NaCl.Ed25519.KeyPairFromSeed(out byte[] ed25519PublicKey, out byte[] ed25519PrivateKey, ed25519Seed);

            byte[] x25519PrivateKey = new byte[32];
            byte[] x25519PublicKey = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(x25519PrivateKey);
            }

            x25519PrivateKey = Chaos.NaCl.Ed25519.ExpandedPrivateKeyFromSeed(ed25519Seed).Take(32).ToArray();
            x25519PublicKey = Chaos.NaCl.MontgomeryCurve25519.GetPublicKey(x25519PrivateKey);

            return new KeyPair
            {
                PublicKey = ed25519PublicKey,
                PrivateKey = ed25519PrivateKey,
                EncryptionPrivateKey = x25519PrivateKey,
                EncryptionPublicKey = x25519PublicKey,
                MnemonicPhrase = null
            };
        }
        public static KeyPair GenerateFromMnemonic(string mnemonicPhrase, string passphrase = "")
        {
            byte[] masterSeed = DeriveSeedFromMnemonic(mnemonicPhrase, passphrase);
            
            byte[] ed25519Seed = masterSeed.Take(32).ToArray();

            Chaos.NaCl.Ed25519.KeyPairFromSeed(out byte[] ed25519PublicKey, out byte[] ed25519PrivateKey, ed25519Seed);

            byte[] x25519PrivateKey = Chaos.NaCl.Ed25519.ExpandedPrivateKeyFromSeed(ed25519Seed).Take(32).ToArray();
            byte[] x25519PublicKey = Chaos.NaCl.MontgomeryCurve25519.GetPublicKey(x25519PrivateKey);

            return new KeyPair
            {
                PublicKey = ed25519PublicKey,
                PrivateKey = ed25519PrivateKey,
                EncryptionPrivateKey = x25519PrivateKey,
                EncryptionPublicKey = x25519PublicKey,
                MnemonicPhrase = mnemonicPhrase
            };
        }

        private static byte [] DeriveSeedFromMnemonic(string mnemonicPhrase, string passphrase)
        {
            string normalizedPhrase = mnemonicPhrase.Trim().ToLowerInvariant().Replace("  ", " ");

            string salt = $"FOREST_MNEMONIC_SALT|{passphrase}";

            var pbkdf2 = new Rfc2898DeriveBytes(
                normalizedPhrase,
                Encoding.UTF8.GetBytes(salt),
                2048
            );

            return pbkdf2.GetBytes(64);
        }
        public static byte[] SignData(byte[] data, KeyPair keyPair)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (keyPair?.PrivateKey == null) throw new ArgumentNullException(nameof(keyPair));

            return Chaos.NaCl.Ed25519.Sign(data, keyPair.PrivateKey);
        }
        public static bool VerifySignature(byte[] data, byte[] signature, byte[] publicKey)
        {
            if (data == null || signature == null || publicKey == null) { return false; }

            try
            {
                return Chaos.NaCl.Ed25519.Verify(signature, data, publicKey);
            }
            catch
            {
                return false;
            }
        }
        public static byte[] ComputeSharedSecret(byte[] myPrivateKey, byte[] peerPublicKey)
        {
            if (myPrivateKey.Length != 32 || peerPublicKey.Length != 32)
            { throw new ArgumentException ("Keys must have 32 bytes"); }

            try
            {
                return Chaos.NaCl.MontgomeryCurve25519.KeyExchange(peerPublicKey, myPrivateKey);
            }
            catch
            {
                throw new CryptographicException("ECDH Error");
            }
        }
        public static string ExportKeyPair(KeyPair keyPair, string encryptionPassword)
        {
            var exportData = new
            {
                Version = "1.0",
                PublicKey = Convert.ToBase64String(keyPair.PublicKey),
                EncryptedPrivateKey = EncryptPrivateKey(keyPair.PrivateKey, encryptionPassword),

                EncryptionPublicKey = Convert.ToBase64String(keyPair.EncryptionPublicKey),
                GeneratedAt = keyPair.GenerateAt.ToString("o")
            };

            return JsonSerializer.Serialize(exportData, new JsonSerializerOptions
            {
                WriteIndented = true
            });
        }
        private static string EncryptPrivateKey(byte[] privateKey, string password)
        {
            byte[] salt = new byte[16];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000);
            byte[] key = pbkdf2.GetBytes(32);

            using var aes = new AesGcm(key);
            byte[] nonce = new byte[12];            
            rng.GetBytes(nonce);
            byte[] ciphertext = new byte[privateKey.Length];
            byte[] tag = new byte[16];

            aes.Encrypt(nonce, privateKey, ciphertext, tag);

            byte[] result = new byte[salt.Length + nonce.Length + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, result, salt.Length, nonce.Length);
            Buffer.BlockCopy(ciphertext, 0, result, salt.Length + nonce.Length, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, salt.Length + nonce.Length + ciphertext.Length, tag.Length);

            return Convert.ToBase64String(result);
        }
    }
    public class PhrasesGenerator
    {
        public static string WebPath = "https://people.sc.fsu.edu/~jburkardt/datasets/words/anagram_dictionary.txt";
        public static string LocalDictionaryPath = "MainFolder/UserInfo/Security/Mnemonic/BaseDictionary/mnemonicdictionary.txt";
        public static string LocalBaseMnemonicPhrasePath = "MainFolder/UserInfo/Security/Mnemonic/";
        public static short WordsCount = 24;
        public PhrasesGenerator()
        {

        }
        public static void CreateMnemonicDictionary()
        {
            try
            {
                var folderName = "MainFolder/UserInfo/Security/Mnemonic/BaseDictionary";
                if (!Directory.Exists(folderName))
                {
                    Directory.CreateDirectory(folderName);
                    if (!File.Exists(LocalDictionaryPath))
                    {
                        var webClient = new WebClient();
                        var dictionary = webClient.DownloadString(WebPath);
                        File.WriteAllText(LocalDictionaryPath, dictionary);
                    }
                }
                else
                {
                    if (!File.Exists(LocalDictionaryPath))
                    {
                        var webClient = new WebClient();
                        var dictionary = webClient.DownloadString(WebPath);
                        File.WriteAllText(LocalDictionaryPath, dictionary);
                    }
                }
            }
            catch (Exception e)
            {
                var logger = new ErrorManager();
                logger.LogError(e.ToString());
            }
        }
        public static void WriteSecureMnemonicPhraseString(string folderName, string fileName)
        {
            var phrase = CreateSecureMnemonicPhraseString().Split(' ');

            var basefolderpath = "MainFolder/UserInfo/Security/Mnemonic";
            var fullPath = $"{basefolderpath}/{folderName}/{fileName}";

            if(!Directory.Exists($"{basefolderpath}/{folderName}"))
            {
                Directory.CreateDirectory($"{basefolderpath}/{folderName}");
                if(!File.Exists(fullPath))
                {
                    File.WriteAllText(fullPath, JsonSerializer.Serialize(phrase));
                }
            }
            else
            {
                if(!File.Exists(fullPath))
                {
                    File.WriteAllText(fullPath, JsonSerializer.Serialize(phrase));
                }
            }
        }
        public static string CreateSecureMnemonicPhraseString()
        {
            try
            {
                var dictionary = File.ReadAllLines(LocalDictionaryPath);

                var words = new List<string>(WordsCount); 

                using (var rng = RandomNumberGenerator.Create())
                {
                    byte[] randomBuffer = new byte[WordsCount * 4];
                    rng.GetBytes(randomBuffer);

                    for (int i = 0; i < WordsCount; i++)
                    {
                        uint randomNumber = BitConverter.ToUInt32(randomBuffer, i * 4);
                        int index = (int)(randomNumber % (uint)dictionary.Length);
                        words.Add(dictionary[index]);
                    }
                }

                return string.Join(" ", words);
            }
            catch (Exception e)
            {
                var logger = new ErrorManager();
                logger.LogError(e.ToString());
                return null;
            }
        }

        public static string CreateChecksum(string phrase)
        {
            var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(phrase));

            string checksum = BitConverter.ToString(hash, 0, 2)
                .Replace("-", "")
                .ToLower();

            return $"{checksum}";
        }
        public static bool CheckUpCheckSum(string phrase, string checksum)
        {
            if (CreateChecksum(phrase) == checksum)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}