public class Contact
{
    public string Name { set; get; }
    public string PublicId {set; get;}
    public bool isPublic { set; get; }
    public string Avatar { set; get; }
    public Contact(string Name, bool isPublic, string PublicId, string Avatar = null)
    {
        this.Name = Name;
        this.isPublic = isPublic;
        this.PublicId = PublicId;
        this.Avatar = Avatar;
    }
    public Contact()
    {
        
    }
}