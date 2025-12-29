using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Xml;

public class ContactService
{
    public class ContactSerializer
    {
        private class ContactDataObject
        {
            public string PublicId { get; set; }
            public string Name { get; set; }
            public bool IsPublic { get; set; }
        }
        public static string SerializeContactToPublicJson(Contact contact)
        {
            var publicContact = new { contact.PublicId, contact.Name, contact.isPublic };
            return JsonSerializer.Serialize(publicContact);
        }
        public static Contact DeserializeFromPublicJson(string json)
        {
            try
            {
                var data = JsonSerializer.Deserialize<ContactDataObject>(json);
                return new Contact(data.Name, data.IsPublic, data.PublicId);
            }
            catch(Exception e)
            {
                var logger = new ErrorManager();
                logger.LogError(e.ToString());
                return null;
            }
        }
    }
    public static class ContactCreator
    {
        public static Contact CreateNewContact(string name, bool isPublic)
        {
            string publicId = GenerateDeterministicPublicId(name, DateTime.UtcNow.Ticks.ToString());
            string privateId = GenerateRandomPrivateId();
            return new Contact(name, isPublic, publicId, privateId);
        }
        private static string GenerateRandomPrivateId()
        {
            byte[] randomBytes = new byte[32]; 
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            
            var Id = string.Empty;
            foreach(var b in randomBytes)
            {
                Id += b.ToString();
            }
            return Id;
        }

        private static string GenerateDeterministicPublicId(string seed, string salt)
        {
            return IdGenerator.GenerateUserId(seed, salt);
        }
    }
    public class ContactWriter
    {
        public readonly static string ContactsPath = "MainFolder/Contacts";
        public static void WriteContact(Contact contact)
        {
            var contactFolderPath = $"{ContactsPath}/{contact.Name}";
            var contactJsonPath = $"{contactFolderPath}/{contact.Name}.json";
            var contactTorrentPath = $"{contactFolderPath}/{contact.Name}.torrent";
            if(!Directory.Exists(contactFolderPath))
            {
                Directory.CreateDirectory(contactFolderPath);
                if(!File.Exists(contactJsonPath))
                {
                    var jsonContact = JsonSerializer.Serialize(contact);
                    File.WriteAllText(contactJsonPath, jsonContact);
                }
            }
        }
    }
}