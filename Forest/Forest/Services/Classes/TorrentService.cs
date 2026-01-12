using System;
using System.Threading.Tasks;
using MonoTorrent;
using MonoTorrent.Client;

public class TorrentService
{
    private readonly ClientEngine _engine;
    public TorrentService()
    {
        var engineSettings = new EngineSettingsBuilder()
        {
            AllowPortForwarding = true, 
        }.ToSettings();

        _engine = new ClientEngine(engineSettings);
    }    
}