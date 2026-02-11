using System;
using System.IO;

public class UserService
{
    public readonly static string UserInfoPath = "MainFolder/UserInfo/ContactInfo/"; //Path of folder with user info
    public static class UserCreator
    {        
        public static (Contact contact, string mnemonicPhrase) CreateUser(string name, bool isPublic, string password = "")
        {            
            string mnemonic = EncryptionService.PhrasesGenerator.CreateSecureMnemonicPhraseString(); //Creating the mnemonic phrase

            var keyPair = EncryptionService.CryptoKeysGenerator.GenerateFromMnemonic(mnemonic); //Generating keyPair

            string publicId = IdGenerator.GeneratePublicUserId(
                keyPair.PublicKeyBase64,
                "FOREST_V1"
            ); //Generating public ID of this user

            var contact = new Contact
            {
                Name = name,
                PublicId = publicId,
                PublicKey = keyPair.PublicKeyBase64,
                EncryptionKey = keyPair.EncryptionPublicKeyBase64,

                IsPublic = isPublic
            }; //Creating contact object

            SaveKeyPairSecurely(keyPair, password); //Saving KeyPair

            SaveMnemonic(mnemonic); //Saving Mnemonic Phrase

            return (contact, mnemonic);
        }        

        private static void SaveKeyPairSecurely(EncryptionService.CryptoKeysGenerator.KeyPair keyPair, string encryptionPassword)
        {
            string encryptedkeyJson = EncryptionService.CryptoKeysGenerator.ExportKeyPair(keyPair, encryptionPassword); //Exporting keyPair to string

            string path = $"MainFolder/UserInfo/Security/CryptoKeys"; //Path value
            //Saving as a json file
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
            string path = $"MainFolder/UserInfo/Security/Mnemonic/UserMnemonicPhrase"; //Path value
            
            //Saving as a txt file
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