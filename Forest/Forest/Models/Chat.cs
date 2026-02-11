using System.Collections.Generic;
using System.Text.Json;

public class Chat 
{
    public string Id { get; set; } //Chat ID
    public string SelfId { set; get; } //Your ID
    public string PeerId { set; get; } //ID of your friend
    public List<Message> Messages = new List<Message>(); //All your messages
    public string PeerName { get; set; } //Your friend's name which you what to give him (only you see it)
    public Chat() {}
    public Chat(string Id, string SelfId, string PeerId, List<Message> Messages, string PeerName)
    {
        this.Id = Id;
        this.SelfId = SelfId;
        this.PeerId = PeerId;
        this.Messages = Messages;
        this.PeerName = PeerName;
    }
    public string ToJson() => JsonSerializer.Serialize(this); //ToJson built-in method
}