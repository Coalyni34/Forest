using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

public class EncryptionService
{
    public class PhrasesGenerator
    {
        public static string WebPath = "https://people.sc.fsu.edu/~jburkardt/datasets/words/anagram_dictionary.txt";
        public static string LocalDictionaryPath = "MainFolder/UserInfo/Security/mnemonicdictionary.txt";
        public static string LocalMnemonicPhrasePath = "MainFolder/UserInfo/Security/mnemonicphrase.json";
        public static short WordsCount = 32;
        public PhrasesGenerator()
        {

        }
        public static void CreateMnemonicDictionary()
        {
            try
            {
                if (!File.Exists(LocalDictionaryPath))
                {
                    var webClient = new WebClient();
                    var dictionary = webClient.DownloadString(WebPath);
                    File.WriteAllText(LocalDictionaryPath, dictionary);
                }
            }
            catch (Exception e)
            {
                var logger = new ErrorManager();
                logger.LogError(e.ToString());
            }
        }
        public static string CreateMnemonicPhraseString()
        {
            try
            {
                var dictionary = File.ReadAllLines(LocalDictionaryPath);
                var words = string.Empty;
                for (short i = 0; i < WordsCount; i++)
                {
                    var rnd = new Random();
                    var newIndex = rnd.Next(0, dictionary.Length - 1);
                    words += dictionary[newIndex] + " ";
                }
                return words.Trim();
            }
            catch (Exception e)
            {
                var logger = new ErrorManager();
                logger.LogError(e.ToString());
                return null;
            }
        }
        public static void CreateMnemonicPhraseFile()
        {
            try
            {
                var dictionary = File.ReadAllLines(LocalDictionaryPath);                
                var words = new List<string>();
                for (short i = 0; i < WordsCount; i++)
                {
                    var rnd = new Random();
                    var newIndex = rnd.Next(0, dictionary.Length - 1);
                    words.Add(dictionary[newIndex]);
                }
                var MnemonicPhrase = new MnemonicPhrase(words);
                var jsonPhrase = JsonSerializer.Serialize(MnemonicPhrase.MnemonicWords);
                File.WriteAllText(LocalMnemonicPhrasePath, jsonPhrase);
            }
            catch (Exception e)
            {
                var logger = new ErrorManager();
                logger.LogError(e.ToString());
            }
        }
    }
}