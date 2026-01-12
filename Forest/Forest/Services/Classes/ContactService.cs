using System;
using System.IO;
using System.Text.Json;

public class ContactService
{
    public class ContactSerializer
    {       
        public static string SerializeContact(Contact contact)
        {            
            return JsonSerializer.Serialize(contact);
        }
        public static Contact DeserializeContact(string json)
        {
            try
            {
                var data = JsonSerializer.Deserialize<Contact>(json);
                return new Contact(data.Name, data.isPublic, data.PublicId);
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
            var contactFolderPath = $"{ContactsPath}/{contact.PublicId}";
            var contactJsonPath = $"{contactFolderPath}/{contact.PublicId}.json";
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