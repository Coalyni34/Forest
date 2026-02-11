using System;
using System.Threading.Tasks;
using MonoTorrent;
using MonoTorrent.Client;

public class TorrentService
{
    private readonly ClientEngine _engine; //Main engine for working with torrents (contacts, chats and another)
    public TorrentService()
    {
        var engineSettings = new EngineSettingsBuilder()
        {
            AllowPortForwarding = true, 
        }.ToSettings(); //Creating engine settings

        _engine = new ClientEngine(engineSettings); //engine object
    }    
}