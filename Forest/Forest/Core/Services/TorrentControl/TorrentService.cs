using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using ForestMSG.Core.Logging;
using ForestMSG.Core.Models;
using ForestMSG.Core.Services.ContactManagement;
using ForestMSG.Core.Services.FileSystem;
using MonoTorrent;
using MonoTorrent.Client;
using MonoTorrent.TrackerServer;
using ReusableTasks;

namespace ForestMSG.Core.Services.TorrentControl
{
    public class TorrentService
    {
        private readonly ClientEngine engine;
        private readonly string _torrentsFolder;

        public TorrentService(string baseFolder = null)
        {
            if(baseFolder == null)
            {
                _torrentsFolder = Path.Combine(DirectoryNames.MainFolder, DirectoryNames.Torrents);
            }
            else
            {
                _torrentsFolder = baseFolder;
            }

            var engineSettings = new EngineSettingsBuilder()
            {
                AllowPortForwarding = true,
                AutoSaveLoadDhtCache = true,
                AllowLocalPeerDiscovery = true
            }.ToSettings();

            engine = new ClientEngine(engineSettings);

            engine.StartAllAsync();
        }
        public async Task StartContactTorrentAsync(string contactFolderPath, string contactFileName)
        {
            var settings = new EngineSettingsBuilder
            {
                AutoSaveLoadDhtCache = true,
                AllowLocalPeerDiscovery = true,
            }.ToSettings();

            var engine = new ClientEngine(settings);

            var contactTorrent = await Task.Run(() =>
                Torrent.Load(Path.Combine(contactFolderPath, contactFileName)));

            var manager = await engine.AddAsync(contactTorrent, contactFolderPath);

            await manager.StartAsync();

            string magnetLink = manager.MagnetLink?.ToV1String() ?? "N/A";

            var logMessage = $"Torrent: {contactTorrent.Name}\n"
            + $"State: {manager.State}\n"
            + $"CanUseDht: {manager.CanUseDht}\n"
            + $"Complete: {manager.Complete}\n"
            + $"Peers Available: {manager.Peers.Available}\n"
            + $"Magnet: {magnetLink}";
            Logger.WriteLog(logMessage);

            manager.TorrentStateChanged += (s, e) =>
                Logger.WriteLog($"State changed to: {manager.State}");
            manager.PeerConnected += (s, e) =>
                Logger.WriteLog($"Peer connected: {e.Peer.Uri}");
        }
        public async Task CreateContactTorrentAsync(string contactJsonPath, string contactId, bool isPrivate = false)
        {
            if (!File.Exists(contactJsonPath))
            {
                throw new FileNotFoundException($"Файл контакта не найден: {contactJsonPath}");
            }

            string torrentPath = Path.Combine(_torrentsFolder, DirectoryNames.TorrentContacts,$"{contactId}.torrent");

            var creator = new TorrentCreator
            {
                Comment = $"Forest Contact: {contactId}",
                CreatedBy = "Forest Messenger v1.0",
                Private = isPrivate,
                Name = $"forest_contact_{contactId}"
            };

            if (!isPrivate)
            {
                var trackers = new List<string>() { };
                creator.Announces.Add(trackers);
            }

            await Task.Run(() => creator.Create(new TorrentFileSource(contactJsonPath), torrentPath));
        }
        public async Task<Contact> FindContactInDHTAsync(string publicId)
        {
            string torrentPath = Path.Combine(_torrentsFolder, $"{publicId}.torrent");
            if (File.Exists(torrentPath))
            {
                string jsonPath = Path.Combine(_torrentsFolder, DirectoryNames.TorrentContacts, publicId, $"{publicId}.json");
                if (File.Exists(jsonPath))
                {
                    string json = await File.ReadAllTextAsync(jsonPath);
                    return JsonSerializer.Deserialize<Contact>(json);
                }
            }

            // 2. TODO: Реальная реализация поиска в DHT
            // Здесь будет код с MonoTorrent для поиска пиров и скачивания
            return null;
        }
        public async Task PublishContactAsync(Contact contact)
        {
            string jsonPath = Path.Combine(_torrentsFolder, DirectoryNames.TorrentContacts, contact.PublicId, $"{contact.PublicId}.json");
            string json = JsonSerializer.Serialize(contact);
            await File.WriteAllTextAsync(jsonPath, json);

            await CreateContactTorrentAsync(jsonPath, contact.PublicId);

            // 3. TODO: Реальная реализация запуска раздачи
            // Здесь будет код с MonoTorrent для старта сидирования
        }
    }
}
