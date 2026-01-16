using System;
using System.Collections.Generic;

public class Message
{
    public ulong Id { get; set; }
    public string SenderId { get; set; }
    public byte[] Data { get; set; } 
    public DateTime SentAt { get; set; } = DateTime.UtcNow;
    public bool IsDownloaded { get; set; } = false;
    public MessageType MessageType { get; set; }
    public List<string> MediaSourcePath { get; set; } = new List<string>();

    public Message(ulong Id, string SenderId, byte[] Data, bool IsDownloaded, MessageType MessageType, List<string> MediaSourcePath)
    {
        this.Id = Id;
        this.SenderId = SenderId;
        this.Data = Data;
        this.IsDownloaded = IsDownloaded;
        this.MessageType = MessageType;
        this.MediaSourcePath = MediaSourcePath;
    }
    public Message()
    {
        
    }
}