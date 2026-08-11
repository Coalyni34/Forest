namespace ForestMSG.Core.Models
{
    public class Contact
    {
        public string Name { set; get; } //Public Name
        public string PublicId { set; get; } //Public ID 
        public string PublicKey { set; get; } //Ed25519 Public Key
        public string EncryptionKey { set; get; } //X25519 ublic Key
        public bool isPrivate { set; get; }  //This value means that will you share your contact by DHT with other users or not

        public Contact(string Name, bool isPrivate, string PublicId)
        {
            this.Name = Name;
            this.isPrivate = isPrivate;
            this.PublicId = PublicId;
        }
        public Contact()
        {

        }
    }
}