using System;
using System.IO;
using System.Text.Json;

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
        public static string SerializeContact(Contact contact)
        {
            var publicContact = new { contact.PublicId, contact.Name, contact.isPublic };
            return JsonSerializer.Serialize(publicContact);
        }
        public static Contact DeserializeContact(string json)
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
    public class ContactCreator
    {
        private readonly static string ContactsPath = "MainFolder/Contacts";
        public static void WriteContact(Contact contact)
        {
            var contactFolderPath = $"{ContactsPath}/{contact.Name}";
            var contactJsonPath = $"{contactFolderPath}/{contact.Name}.json";
            //var contactTorrentPath = $"{contactFolderPath}/{contact.Name}.torrent"; Soon
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