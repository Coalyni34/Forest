using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Forest.Models;
using ForestMSG.Core.Enums;
using ForestMSG.Core.Logging;
using ForestMSG.Core.Services.ContactManagement;
using ForestMSG.Core.Services.FileSystem;
using ForestMSG.Core.Services.TorrentControl;
using static ForestMSG.Core.Services.Encryption.EncryptionService;

namespace ForestMSG.Core.Services.Messaging
{
    public class MessageSendService
    {
        private readonly MessageEncoder _encoder;
        private readonly ArchiveService _archiveService;
        private readonly TorrentService.ContactTorrentService _torrentService;
        private readonly HandshakeService _handshakeService;
        private readonly ContactService _contactService;
        private readonly string _chatsFolder;

        public MessageSendService(
            MessageEncoder encoder,
            ArchiveService archiveService,
            TorrentService.ContactTorrentService torrentService,
            HandshakeService handshakeService,
            ContactService contactService)
        {
            _encoder = encoder;
            _archiveService = archiveService;
            _torrentService = torrentService;
            _handshakeService = handshakeService;
            _contactService = contactService;

            _chatsFolder = Path.Combine(DirectoryNames.MainFolder, DirectoryNames.Chats);
            Directory.CreateDirectory(_chatsFolder);
        }

        public async Task<Message> SendMessageAsync(
            string chatId,
            string text,
            List<string> mediaPaths = null,
            string password = null
        )
        {
            try
            {
                Logger.WriteLog($"[MessageSendService] Отправка сообщения в чат {chatId}");

                var session = _handshakeService.GetSession(chatId);
                if (session == null)
                {
                    throw new InvalidOperationException($"Сессия для чата {chatId} не найдена. Сначала инициируйте чат.");
                }

                var keyPair = await _contactService.LoadKeysAsync(session.SelfId, password ?? "");
                if (keyPair == null)
                {
                    throw new InvalidOperationException($"Не удалось загрузить ключи для {session.SelfId}");
                }

                var message = new Message
                {
                    ChatId = chatId,
                    SenderId = session.SelfId                    
                };
            }
            catch
            {
                
            }
        }
    }
}