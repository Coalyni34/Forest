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
    public async Task Test(string path, string directory)
    {
        var torrent = await Torrent.LoadAsync(path);
        var manager = await _engine.AddAsync(torrent, directory);
        manager.PeersFound += (sender, e) => 
            Console.WriteLine($"Найдено пиров: {e.NewPeers}");
        manager.TorrentStateChanged += (sender, e) => 
            Console.WriteLine($"Состояние изменилось: {e.NewState}");
            await manager.StartAsync();

        Console.WriteLine($"Загрузка начата: {torrent.Name}");
        while (manager.State != TorrentState.Stopped)
        {
            Console.WriteLine($"Прогресс: {manager.Progress:F2}%, " +
                              $"Скорость: {manager.Monitor.DownloadRate / 1024:F1} КБ/с");

            await Task.Delay(1000);

            if (manager.Progress == 100.0)
            {
                Console.WriteLine("Загрузка завершена!");
                break;
            }
        }
    }
}