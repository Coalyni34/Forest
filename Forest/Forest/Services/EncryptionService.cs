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