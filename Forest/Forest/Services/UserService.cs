using System;
using System.IO;

public class UserService
{
    public readonly static string UserInfoPath = "MainFolder/UserInfo/ContactInfo/";
    public static class UserCreator
    {        
        public static (Contact contact, string mnemonicPhrase) CreateUser(string name, bool isPublic, string password = "")
        {            
            string mnemonic = EncryptionService.PhrasesGenerator.CreateSecureMnemonicPhraseString();

            var keyPair = EncryptionService.CryptoKeysGenerator.GenerateFromMnemonic(mnemonic);

            string publicId = IdGenerator.GeneratePublicUserId(
                keyPair.PublicKeyBase64,
                "FOREST_V1"
            );

            var contact = new Contact
            {
                Name = name,
                PublicId = publicId,
                PublicKey = keyPair.PublicKeyBase64,
                EncryptionKey = keyPair.EncryptionPublicKeyBase64,

                IsPublic = isPublic
            };

            SaveKeyPairSecurely(keyPair, password);

            SaveMnemonic(mnemonic);

            return (contact, mnemonic);
        }        

        private static void SaveKeyPairSecurely(EncryptionService.CryptoKeysGenerator.KeyPair keyPair, string encryptionPassword)
        {
            string encryptedkeyJson = EncryptionService.CryptoKeysGenerator.ExportKeyPair(keyPair, encryptionPassword);

            string path = $"MainFolder/UserInfo/Security/CryptoKeys";
            if(!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
                if(!File.Exists($"{path}/UserCryptoKeys.json"))
                {
                    File.WriteAllText($"{path}/UserCryptoKeys.json", encryptedkeyJson);
                }                
            }
        }
        private static void SaveMnemonic(string mnemonic)
        {
            string path = $"MainFolder/UserInfo/Security/Mnemonic/UserMnemonicPhrase";
            
            if(!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
                if(!File.Exists($"{path}/UserMnemonicPhrase.txt"))
                {
                    File.WriteAllText($"{path}/UserMnemonicPhrase.txt", mnemonic);                
                }
            }
        }
    }
}