public class Contact
{
    public string Name { set; get; } //Public Name
    public string Avatar { set; get; } //Public Avatar
    public string PublicId { set; get;} //Public ID 
    public string PublicKey { set; get; } //Public Key, which you need for creating your cryptokeys
    public string EncryptionKey { set; get; } //Encryption Key, which is not public
    public bool isPrivate { set; get; }  //This value means that will you share your contact with other users or not
    
    public Contact(string Name, bool isPrivate, string PublicId, string Avatar = "")
    {
        this.Name = Name;
        this.isPrivate = isPrivate;
        this.PublicId = PublicId;
        this.Avatar = Avatar;
    }
    public Contact()
    {
        
    }
}