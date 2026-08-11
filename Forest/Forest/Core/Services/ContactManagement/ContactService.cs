using System;
using System.IO;
using System.Text.Json;
using ForestMSG.Core.ErrorManagement;
using ForestMSG.Core.Models;

namespace ForestMSG.Core.Services.ContactManagement
{
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
                catch (Exception e)
                {
                    var logger = new ErrorHandler();
                    logger.LogError(e.ToString());
                    return null; //If we have some problems => we'll log errors and return null value
                }
            }
        }
    }
}