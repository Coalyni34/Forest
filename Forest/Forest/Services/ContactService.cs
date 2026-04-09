using System;
using System.IO;
using System.Text.Json;

public class ContactService
{
    public class ContactSerializer
    {       
        public static string SerializeContact(Contact contact)
        {            
            return JsonSerializer.Serialize(contact); //Serializing contact to string
        }
        public static Contact DeserializeContact(string json)
        {
            try
            {
                return JsonSerializer.Deserialize<Contact>(json); //Deserializing contact from json
            }
            catch(Exception e)
            {
                var logger = new ErrorManager();
                logger.LogError(e.ToString());
                return null; //If we have some problems => we'll log errors and return null value
            }
        }
    }    
    public class ContactCreator
    {
        private readonly static string ContactsPath = "MainFolder/Contacts"; //Contacts folder's path
        public static void WriteContact(Contact contact)
        {
            var contactFolderPath = $"{ContactsPath}/{contact.PublicId}"; //Folder of the current contact
            var contactJsonPath = $"{contactFolderPath}/{contact.PublicId}.json"; //Json file of the current contact
            if(!Directory.Exists(contactFolderPath)) //Checking folder of the contact
            {
                Directory.CreateDirectory(contactFolderPath); //Creating folder
                if(!File.Exists(contactJsonPath))
                {
                    File.WriteAllText(contactJsonPath, JsonSerializer.Serialize(contact));//Writing contact as a json file.
                }
            }
        }        
        public static void CreateContact()
        {
            
        }
    }
}