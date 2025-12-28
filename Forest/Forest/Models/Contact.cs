using System;
using System.Text.Json;

public class Contact
{
    public string Name { set; get; }
    public string PrivateId { set; get; }
    public string PublicId {set; get;}
    public bool isPublic { set; get; }
    public Contact()
    {
        
    }
    public Contact(string PublicId, string Name, bool isPublic, string Salt = "forest_messenger_v1")
    {
        this.Name = Name;
        this.isPublic = isPublic;
        this.PublicId = PublicId;

        PrivateId = IdGenerator.GenerateUserId(PublicId, Salt);
    }    
    public static Contact Deserialize(string json)
    {
        try
        {
            if(!string.IsNullOrEmpty(json))
            {
                var contactToDeserialize = JsonSerializer.Deserialize<Contact>(json);
                return contactToDeserialize;
            }
            else
            {
                return null;
            }
        }
        catch(Exception e)
        {
            var logger = new ErrorManager();
            logger.LogError(e.ToString());
            return null;
        }
    }
    public string Serialize()
    {
        try
        {
            if(PublicId != string.Empty && Name != string.Empty)
            {
                var contactToSerialize = new Contact(PublicId, Name, isPublic);
                var contactJson = JsonSerializer.Serialize(contactToSerialize);
                return contactJson;
            }                       
            else
            {
                return null;
            }
        }
        catch(Exception e)
        {
            var logger = new ErrorManager();
            logger.LogError(e.ToString());
            return null;
        }
    }
}