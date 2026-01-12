public class Contact
{
    public string Name { set; get; }
    public string Avatar { set; get; }
    public string PublicId { set; get;}
    public string PublicKey { set; get; }
    public string EncryptionKey { set; get; }
    public bool IsPublic { set; get; }   
    
    public Contact(string Name, bool IsPublic, string PublicId, string Avatar = "")
    {
        this.Name = Name;
        this.IsPublic = IsPublic;
        this.PublicId = PublicId;
        this.Avatar = Avatar;
    }
    public Contact()
    {
        
    }
}