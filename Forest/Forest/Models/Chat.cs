using System;
using System.Collections.Generic;

public class Chat
{
    public string Id { get; set; }
    public string SelfId { set; get; }
    public string PeerId { set; get; }
    public List<Message> Messages = new List<Message>();
}