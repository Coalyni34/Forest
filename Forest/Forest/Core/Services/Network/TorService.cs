using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using ForestMSG.Core.Logging;

namespace ForestMSG.Core.Services.Network
{
    public class TorService : IDisposable
    {
        private bool _isRunning;
        private readonly string _proxyHost = "127.0.0.1";
        private readonly int _proxyPort = 9050;
        private readonly string _torrcPath;
        private readonly string _torDataDir;
        private readonly string _os;
        private System.Diagnostics.Process _torProcess;

        public TorService(string torDataDir = null)
        {
            _os = GetOperatingSystem();
            _torDataDir = torDataDir ?? Path.Combine(Path.GetTempPath(), "ForestTor");
            _torrcPath = Path.Combine(_torDataDir, "torrc");
            Directory.CreateDirectory(_torDataDir);
        }

        private string GetOperatingSystem()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return "Windows";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return "Linux";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return "macOS";
            return "Unknown";
        }

        public async Task StartAsync(bool useBridges = true)
        {
            try
            {
                Logger.WriteLog($"[TorService] Запуск на {_os}...");

                List<string> bridges = null;
                if (useBridges)
                {
                    bridges = await FetchBridgesFromMoatAsync();
                }

                GenerateTorrc(bridges);

                await StartTorProcessAsync();

                await WaitForTorReadyAsync();

                _isRunning = true;
                Logger.WriteLog($"[TorService] Запущен на {_os} с {bridges?.Count ?? 0} мостами");
            }
            catch (Exception ex)
            {
                Logger.WriteLog($"[TorService] Ошибка запуска: {ex.Message}");
                _isRunning = false;
                throw;
            }
        }

        private async Task<List<string>> FetchBridgesFromMoatAsync()
        {
            try
            {
                using var httpClient = new HttpClient();
                httpClient.Timeout = TimeSpan.FromSeconds(30);

                var requestBody = new { bridgeType = "obfs4", version = "1.0" };
                var content = new StringContent(
                    JsonSerializer.Serialize(requestBody),
                    System.Text.Encoding.UTF8,
                    "application/json"
                );

                var response = await httpClient.PostAsync(
                    "https://bridges.torproject.org/moat",
                    content
                );

                if (!response.IsSuccessStatusCode)
                    throw new Exception($"Moat API ошибка: {response.StatusCode}");

                var responseJson = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(responseJson);
                var root = doc.RootElement;

                if (root.TryGetProperty("error", out var error))
                    throw new Exception($"Moat API: {error.GetString()}");

                if (root.TryGetProperty("bridges", out var bridgesElement))
                {
                    var bridgesList = new List<string>();
                    foreach (var bridge in bridgesElement.EnumerateArray())
                        bridgesList.Add(bridge.GetString());
                    return bridgesList;
                }

                throw new Exception("Не удалось получить мосты");
            }
            catch (Exception ex)
            {
                Logger.WriteLog($"[TorService] Ошибка получения мостов: {ex.Message}");
                return new List<string>();
            }
        }

        private void GenerateTorrc(List<string> bridges)
        {
            var config = new List<string>();
            config.Add("# Torrc сгенерирован Forest Messenger");
            config.Add($"DataDirectory {Path.Combine(_torDataDir, "data")}");
            config.Add($"SocksPort {_proxyPort}");
            config.Add("Log notice file /dev/null");

            if (bridges != null && bridges.Any())
            {
                config.Add("UseBridges 1");
                foreach (var bridge in bridges)
                    config.Add($"Bridge {bridge}");

                config.Add("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy");
                config.Add("ClientTransportPlugin webtunnel exec /usr/bin/webtunnel");
            }

            File.WriteAllLines(_torrcPath, config);
            Logger.WriteLog($"[TorService] torrc сгенерирован");
        }

        private async Task StartTorProcessAsync()
        {
            string torPath = GetTorExecutablePath();

            if (!File.Exists(torPath))
            {
                throw new Exception($"Tor не найден по пути: {torPath}. Установите Tor.");
            }

            var startInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = torPath,
                Arguments = $"-f \"{_torrcPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            if (_os == "Windows")
            {
                startInfo.CreateNoWindow = true;
                startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            }

            var process = System.Diagnostics.Process.Start(startInfo);

            Logger.WriteLog($"[TorService] Tor запущен (PID: {process?.Id})");
            await Task.CompletedTask;
        }

        private string GetTorExecutablePath()
        {
            if (_os == "Windows")
            {
                var paths = new[]
                {
                    @"C:\Program Files\Tor\Tor.exe",
                    @"C:\Users\Default\AppData\Roaming\tor\Tor.exe",
                    @"C:\Program Files (x86)\Tor\Tor.exe",
                    "tor.exe"
                };

                foreach (var path in paths)
                {
                    if (File.Exists(path))
                        return path;
                }
                return "tor.exe";
            }
            else if (_os == "Linux")
            {
                var paths = new[]
                {
                    "/usr/bin/tor",
                    "/usr/local/bin/tor"
                };

                foreach (var path in paths)
                {
                    if (File.Exists(path))
                        return path;
                }
                return "tor";
            }
            else if (_os == "macOS")
            {
                var paths = new[]
                {
                    "/usr/local/bin/tor",
                    "/usr/bin/tor"
                };

                foreach (var path in paths)
                {
                    if (File.Exists(path))
                        return path;
                }
                return "tor";
            }

            throw new PlatformNotSupportedException($"OS {_os} не поддерживается");
        }

        private async Task WaitForTorReadyAsync(int timeoutSeconds = 30)
        {
            Logger.WriteLog("[TorService] Ожидание готовности Tor...");

            for (int i = 0; i < timeoutSeconds; i++)
            {
                if (await IsTorAvailableAsync())
                {
                    Logger.WriteLog("[TorService] Tor готов");
                    return;
                }
                await Task.Delay(1000);
            }

            throw new TimeoutException("Tor не запустился за отведённое время");
        }

        public async Task<bool> IsTorAvailableAsync()
        {
            try
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(_proxyHost, _proxyPort);
                return true;
            }
            catch
            {
                return false;
            }
        }


        public HttpClient CreateHttpClient()
        {
            if (!_isRunning)
                throw new InvalidOperationException("Tor не запущен");

            var handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"socks5://{_proxyHost}:{_proxyPort}"),
                UseProxy = true,
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
            };
            return new HttpClient(handler);
        }

        public async Task<string> GetAsync(string url)
        {
            using var client = CreateHttpClient();
            var response = await client.GetAsync(url);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        public async Task StopAsync()
        {
            _isRunning = false;

            if (_torProcess != null && !_torProcess.HasExited)
            {
                _torProcess.Kill();
                _torProcess.WaitForExit();
                _torProcess.Dispose();
                _torProcess = null;
                Logger.WriteLog("[TorService] Процесс Tor остановлен");
            }

            Logger.WriteLog("[TorService] Остановлен");
            await Task.CompletedTask;
        }

        public async Task RestartAsync(bool useBridges = true)
        {
            await StopAsync();
            await Task.Delay(3000);
            await StartAsync(useBridges);
        }

        public void Dispose()
        {
            _isRunning = false;
        }
    }
}