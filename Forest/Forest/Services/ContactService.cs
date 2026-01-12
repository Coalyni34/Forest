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
                return JsonSerializer.Deserialize<Contact>(json);
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
                    File.WriteAllText(contactJsonPath, JsonSerializer.Serialize(contact));
                }
            }
        }
    }
}