using System;
using System.Collections.Generic;

public class Message
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string SenderId { get; set; } = string.Empty;
    public string RecipientId { get; set; } = string.Empty;
    public byte[] Data { get; set; } = Array.Empty<byte>();
    public DateTime SentAt { get; set; } = DateTime.UtcNow;
    public bool IsDownloaded { get; set; } = false;
    public MessageType messageType { get; set; }
    public List<string> MediaSourcePath { get; set; } = new List<string>();
}