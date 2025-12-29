using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
public class EncryptionService
{
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
        public static string CreateSecureMnemonicPhraseString()
        {
            try
            {
                var dictionary = File.ReadAllLines(LocalDictionaryPath);
                var words = new List<string>();

                var rng = RandomNumberGenerator.Create();

                for (short i = 0; i < WordsCount; i++)
                {
                    byte[] randomBytes = new byte[4];
                    rng.GetBytes(randomBytes);

                    uint randomNumber = BitConverter.ToUInt32(randomBytes, 0);

                    int index = GetUniformRandomIndex(randomNumber, dictionary.Length);

                    words.Add(dictionary[index]);
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

        private static int GetUniformRandomIndex(uint random, int length)
        {
            uint maxAcceptable = uint.MaxValue - (uint.MaxValue % (uint)length);

            while (random >= maxAcceptable)
            {
                random = random / 2 + 12345;
            }

            return (int)(random % (uint)length);
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
    }
}