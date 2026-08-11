using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using ForestMSG.Core.Logging;
using ForestMSG.Core.Services.ContactManagement;
using MonoTorrent;
using MonoTorrent.Client;
using MonoTorrent.TrackerServer;
using ReusableTasks;

namespace ForestMSG.Core.Services.TorrentControl
{
    public class TorrentService
    {
        private readonly ClientEngine engine;
        private readonly string torrentsFolder;
        public TorrentService(string baseFolder)
        {
            torrentsFolder = baseFolder;
            if (!File.Exists(torrentsFolder))
            {
                Directory.CreateDirectory(torrentsFolder);
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


            var qrCodeCreator = new QRCodeCreator();
            qrCodeCreator.CreateQRCode(magnetLink, Path.Combine(contactFolderPath, $"{contactFileName}.png"));

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
        public async Task CreateContactTorrentAsync(string contactPath, string contactId, bool isOnlyDHT, bool isPrivate = false)
        {
            if (!File.Exists(contactPath))
            {
                throw new FileNotFoundException($"Файл контакта не найден: {contactPath}");
            }

            string torrentFileName = $"{contactId}.torrent";
            string torrentPath = Path.Combine($"{torrentsFolder}/{contactId}/", torrentFileName);

            var creator = new TorrentCreator
            {
                Comment = $"Forest Contact: {contactId}",
                CreatedBy = "Forest Messenger v0.0.1",

                Private = isPrivate,
                Name = $"forest_contact_{contactId}"
            };

            if (!isOnlyDHT)
            {
                var trackers = new List<string>() {
            };
                creator.Announces.Add(trackers);
            }

            creator.Hashed += (o, e) =>
            {
                Logger.WriteLog($"[ForestTorrentCreator] Hashing: {e.OverallCompletion:F1}%");
            };

            await Task.Run(() => creator.Create(new TorrentFileSource(contactPath), torrentPath));
        }
    }
}
