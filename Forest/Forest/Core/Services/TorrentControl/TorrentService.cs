using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using ForestMSG.Core.ErrorManagement;
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
        public class ContactTorrentService : TorrentService
        {
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

                string contactTorrentFolder = Path.Combine(_contactsTorrentFolder, contactId);
                Directory.CreateDirectory(contactTorrentFolder);

                string torrentPath = Path.Combine(contactTorrentFolder, $"{contactId}.torrent");

                var creator = new TorrentCreator
                {
                    Comment = $"Forest Contact: {contactId}",
                    CreatedBy = "Forest Messenger v1.0",
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
                string contactFolder = Path.Combine(_contactsFolder, publicId);
                string jsonPath = Path.Combine(contactFolder, $"{publicId}.json");

                if (File.Exists(jsonPath))
                {
                    string json = await File.ReadAllTextAsync(jsonPath);
                    return JsonSerializer.Deserialize<Contact>(json);
                }

                try
                {
                    string infoHashHex = GenerateInfoHashFromPublicId(publicId);
                    var infoHash = InfoHash.FromHex(infoHashHex);

                    var magnetLink = new MagnetLink(infoHash, publicId, PublicTrackers);

                    var manager = await engine.AddAsync(magnetLink, _torrentsFolder);
                    await manager.StartAsync();

                    string downloadPath = Path.Combine(_torrentsFolder, "Downloads");
                    Directory.CreateDirectory(downloadPath);

                    var jsonFile = manager.Torrent.Files.FirstOrDefault(f =>
                f.Path.EndsWith(".json", StringComparison.OrdinalIgnoreCase));


                    if (jsonFile == null)
                    {
                        Logger.WriteLog($"[TorrentService] JSON файл не найден в торренте {publicId}");
                        return null;
                    }

                    while (manager.Bitfield.PercentComplete < 100 && manager.State != TorrentState.Seeding)
                    {
                        await Task.Delay(1000);
                    }

                    string downloadedFilePath = Path.Combine(downloadPath, publicId, jsonFile.Path);
                    if (!File.Exists(downloadedFilePath))
                    {
                        Logger.WriteLog($"[TorrentService] Файл не скачан: {downloadedFilePath}");
                        return null;
                    }

                    string json = await File.ReadAllTextAsync(downloadedFilePath);
                    var contact = JsonSerializer.Deserialize<Contact>(json);

                    await manager.StopAsync();

                    if (contact != null && contact.PublicId == publicId)
                    {
                        Directory.CreateDirectory(contactFolder);
                        await File.WriteAllTextAsync(jsonPath, json);

                        Logger.WriteLog($"[TorrentService] Контакт {publicId} найден и сохранён локально");
                        return contact;
                    }

                    return null;

                }
                catch (Exception e)
                {
                    ErrorHandler.LogError($"[TorrentService] {e}");
                    return null;
                }
            }
            public async Task PublishContactAsync(Contact contact)
            {
                if (contact == null)
                    throw new ArgumentNullException(nameof(contact));

                string contactFolder = Path.Combine(_contactsFolder, contact.PublicId);
                Directory.CreateDirectory(contactFolder);

                string jsonPath = Path.Combine(contactFolder, $"{contact.PublicId}.json");
                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(contact, options);
                await File.WriteAllTextAsync(jsonPath, json);

                await CreateContactTorrentAsync(jsonPath, contact.PublicId, contact.IsPrivate);

                string torrentPath = Path.Combine(_contactsTorrentFolder, contact.PublicId, $"{contact.PublicId}.torrent");
                var torrent = await Task.Run(() => Torrent.Load(torrentPath));

                var manager = await engine.AddAsync(torrent, _contactsFolder);
                await manager.StartAsync();

                Logger.WriteLog($"[TorrentService] Контакт {contact.PublicId} опубликован");
                Logger.WriteLog($"  State: {manager.State}");
                Logger.WriteLog($"  Magnet: {manager.MagnetLink?.ToV1String() ?? "N/A"}");

                manager.TorrentStateChanged += (s, e) =>
                    Logger.WriteLog($"State changed to: {manager.State}");
                manager.PeerConnected += (s, e) =>
                    Logger.WriteLog($"Peer connected: {e.Peer.Uri}");
            }
            private string GenerateInfoHashFromPublicId(string publicId)
            {
                using var sha1 = System.Security.Cryptography.SHA1.Create();
                byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(publicId));
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
        private readonly ClientEngine engine;
        private readonly string _torrentsFolder;

        private readonly string _contactsTorrentFolder;
        private readonly string _contactsFolder;
        private readonly List<string> PublicTrackers = new List<string>()
        {

        };

        public TorrentService(string baseFolder = null)
        {
            string mainFolder = baseFolder ?? DirectoryNames.MainFolder;

            _contactsFolder = Path.Combine(mainFolder, DirectoryNames.Contacts);
            _torrentsFolder = Path.Combine(mainFolder, DirectoryNames.Torrents);
            _contactsTorrentFolder = Path.Combine(_torrentsFolder, DirectoryNames.TorrentContacts);

            Directory.CreateDirectory(_contactsFolder);
            Directory.CreateDirectory(_torrentsFolder);
            Directory.CreateDirectory(_contactsTorrentFolder);

            var engineSettings = new EngineSettingsBuilder()
            {
                AllowPortForwarding = true,
                AutoSaveLoadDhtCache = true,
                AllowLocalPeerDiscovery = true
            }.ToSettings();

            engine = new ClientEngine(engineSettings);

            engine.StartAllAsync();
        }
    }
}
