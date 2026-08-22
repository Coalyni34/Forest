using System;
using System.Threading.Tasks;
using ForestMSG.Core.Services.Network;
using MonoTorrent.PieceWriter;

namespace ForestMSG.Tests
{
    public class TorServiceTest
    {
        public static async Task RunTest()
        {
            Console.WriteLine("========================================");
            Console.WriteLine("Тестирование TorService");
            Console.WriteLine("========================================\n");

            var torService = new TorService();

            Console.WriteLine("[1/6] Запуск Tor...");
            try
            {
                await torService.StartAsync(useBridges: true);
                Console.WriteLine("Tor запущен\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка запуска Tor: {ex.Message}");
                Console.WriteLine("Убедитесь, что Tor установлен в системе.");
                Console.WriteLine("Для Linux: sudo apt install tor");
                Console.WriteLine("Для macOS: brew install tor");
                Console.WriteLine("Для Windows: скачайте Tor Expert Bundle\n");
                return;
            }

            Console.WriteLine("[2/6] Проверка доступности SOCKS5 прокси...");
            bool isAvailable = await torService.IsTorAvailableAsync();

            if (isAvailable)
            {
                Console.WriteLine($"SOCKS5 прокси доступен на 127.0.0.1:9050\n");
            }
            else
            {
                Console.WriteLine("SOCKS5 прокси недоступен\n");
                await torService.StopAsync();
                return;
            }

            Console.WriteLine("[3/6] Создание HTTP-клиента через Tor...");
            try
            {
                using var client = torService.CreateHttpClient();
                Console.WriteLine($"HTTP-клиент создан\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка создания HTTP-клиента: {ex.Message}\n");
            }

            Console.WriteLine("[4/6] Запрос к check.torproject.org...");
            try
            {
                string html = await torService.GetAsync("https://check.torproject.org");
                
                var ipMatch = System.Text.RegularExpressions.Regex.Match(
                    html,
                    @"<strong>(\d+\.\d+\.\d+\.\d+)</strong>"
                );

                if (ipMatch.Success)
                {
                    string ip = ipMatch.Groups[1].Value;
                    Console.WriteLine($"Запрос выполнен через Tor. Ваш IP: {ip}");
                    
                    if (ip.StartsWith("10.") || ip.StartsWith("192.168.") || ip.StartsWith("172.16."))
                    {
                        Console.WriteLine("IP выглядит как локальный. Возможно, Tor не работает корректно.\n");
                    }
                    else
                    {
                        Console.WriteLine("IP адрес не локальный. Tor работает корректно!\n");
                    }
                }
                else
                {
                    Console.WriteLine("Не удалось найти IP в ответе, но запрос выполнен успешно.\n");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка запроса: {ex.Message}");
                Console.WriteLine("Проверьте соединение с интернетом.\n");
            }

            Console.WriteLine("[5/6] Проверка обновления цепей...");
            try
            {
                string before = await torService.GetAsync("https://check.torproject.org");
                var beforeIp = System.Text.RegularExpressions.Regex.Match(
                    before,
                    @"<strong>(\d+\.\d+\.\d+\.\d+)</strong>"
                );

                await torService.RestartAsync(useBridges: true);

                string after = await torService.GetAsync("https://check.torproject.org");
                var afterIp = System.Text.RegularExpressions.Regex.Match(
                    after,
                    @"<strong>(\d+\.\d+\.\d+\.\d+)</strong>"
                );

                if (beforeIp.Success && afterIp.Success)
                {
                    if (beforeIp.Groups[1].Value != afterIp.Groups[1].Value)
                    {
                        Console.WriteLine($"Цепь обновлена. Новый IP: {afterIp.Groups[1].Value}\n");
                    }
                    else
                    {
                        Console.WriteLine($"IP не изменился. Возможно, цепь не обновлена.\n");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка обновления цепи: {ex.Message}\n");
            }

            Console.WriteLine("[6/6] Статус TorService:");
            Console.WriteLine($"Запущен: {await torService.IsTorAvailableAsync()}");
            Console.WriteLine($"SOCKS5 порт: 9050");
            Console.WriteLine($"Мосты: включены");

            Console.WriteLine("\n========================================");
            if (await torService.IsTorAvailableAsync())
            {
                Console.WriteLine("TorService работает корректно!");
                Console.WriteLine("Вы можете делать анонимные запросы в Clearnet.");
            }
            else
            {
                Console.WriteLine("TorService не работает.");
                Console.WriteLine("Проверьте: установлен ли Tor, не заблокирован ли порт 9050.");
            }
            Console.WriteLine("========================================\n");

            await torService.StopAsync();
        }
    }
}