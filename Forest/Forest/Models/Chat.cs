using System;
using System.Collections.Generic;

public class Chat
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string[] SenderIds = new string[2];
    public string Keys { set; get; } = string.Empty;
    public List<Message> Messages = new List<Message>();
}