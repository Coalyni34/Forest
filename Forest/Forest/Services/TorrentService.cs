using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using MonoTorrent;
using MonoTorrent.Client;
using MonoTorrent.TrackerServer;
using ReusableTasks;

public class TorrentService
{
    private readonly ClientEngine engine;
    private readonly string torrentsFolder;
    public TorrentService(string baseFolder)
    {
        torrentsFolder = baseFolder;
        if(!File.Exists(torrentsFolder))
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

        Console.WriteLine($"Torrent: {contactTorrent.Name}");
        Console.WriteLine($"State: {manager.State}");
        Console.WriteLine($"CanUseDht: {manager.CanUseDht}");
        Console.WriteLine($"Complete: {manager.Complete}");
        Console.WriteLine($"Peers Available: {manager.Peers.Available}");

        string magnetLink = manager.MagnetLink?.ToV1String() ?? "N/A";
        Console.WriteLine($"Magnet: {magnetLink}");

        manager.TorrentStateChanged += (s, e) =>
            Console.WriteLine($"State changed to: {manager.State}");
        manager.PeerConnected += (s, e) =>
            Console.WriteLine($"Peer connected: {e.Peer.Uri}");
    }
    public async Task CreateContactTorrentAsync(string contactPath, string contactId, bool isOnlyDHT, bool isPrivate = false)
    {
        if (!File.Exists(contactPath))
        {
            throw new FileNotFoundException($"Файл контакта не найден: {contactPath}");
        }

        string torrentFileName = $"{contactId}.torrent";
        string torrentPath = Path.Combine(torrentsFolder+$"/{contactId}/", torrentFileName);

        var creator = new TorrentCreator
        {
            Comment = $"Forest Contact: {contactId}",
            CreatedBy = "Forest Messenger v0.0.1",

            Private = isPrivate,
            Name = $"forest_contact_{contactId}"
        };

        if(!isOnlyDHT)
        {
            var trackers = new List<string>() { 
            "udp://tracker.opentrackr.org:1337/announce",
            "udp://tracker.coppersurfer.tk:6969/announce",
            "udp://tracker.leechers-paradise.org:6969/announce"
            };
            creator.Announces.Add(trackers);
        }

        creator.Hashed += (o, e) =>
        {
            Console.WriteLine($"[ForestTorrentCreator] Hashing: {e.OverallCompletion:F1}%");
        };

        await Task.Run(() => creator.Create(new TorrentFileSource(contactPath), torrentPath));

        var torrent = await Task.Run(() => Torrent.Load(torrentPath));
    }    
}