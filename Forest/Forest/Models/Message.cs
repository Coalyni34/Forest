using System;

public class Message
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string SenderId { get; set; } = string.Empty;
    public string RecipientId { get; set; } = string.Empty;
    public byte[] EncryptedData { get; set; } = Array.Empty<byte>();
    public string MagnetLink { get; set; } = string.Empty;
    public DateTime SentAt { get; set; } = DateTime.Now;
    public bool IsDownloaded { get; set; } = false;
    public MessageType messageType { get; set; }
    public string MediaSourcePath { get; set; } = string.Empty;
}