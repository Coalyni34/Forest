using System;
using System.Collections.Generic;
using ForestMSG.Enums;

namespace Forest.Models
{
    public class Message
    {
        public ulong Id { get; set; } //Message ID
        public string SenderId { get; set; } //Sender ID
        public byte[] Data { get; set; } //Byte Data of the message
        public DateTime SentAt { get; set; } = DateTime.UtcNow; //SentAt Date
        public bool IsDownloaded { get; set; } = false; //Is the message downloaded or not
        public MessageType MessageType { get; set; } //Type of the message
        public List<string> MediaSourcePath { get; set; } = new List<string>(); //Magnetlinks of the media which the message contains

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
}