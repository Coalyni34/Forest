using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using ForestMSG.Core.Services.FileSystem;

namespace ForestMSG.Core.Logging
{
    public class Logger
    {
        public class Log
        {
            public string LogText { set; get; }
            public DateTime LogDateTime { set; get; }
            public Log() { }
            public Log(string LogText, DateTime LogDateTime)
            {
                this.LogText = LogText;
                this.LogDateTime = LogDateTime;
            }
        }
        public static void WriteLog(string LogText)
        {     
            var folderPath = Path.Combine(DirectoryNames.MainFolder, $"{DateTime.Now:dd:MM:yyyy}");
            if (!Directory.Exists(folderPath))
            {
                Directory.CreateDirectory(folderPath);
                Console.WriteLine($"[Logger] {folderPath} был создан | {DateTime.Now:g}");
            }
           
            var jsonFileName = $"Log_{DateTime.Now:dd:MM:yyyy}.json";
            var jsonFilePath = Path.Combine(folderPath, jsonFileName);

            try
            {
                var todayLogs = new List<Log>();

                if (File.Exists(jsonFilePath))
                {
                    todayLogs = JsonSerializer.Deserialize<List<Log>>(File.ReadAllText(jsonFilePath));
                }

                var log = new Log
                {
                    LogText = LogText,
                    LogDateTime = DateTime.Now
                };
                todayLogs.Add(log);

                var jsonLog = JsonSerializer.Serialize(todayLogs);

                File.WriteAllText(jsonFilePath, jsonLog);
            }
            catch (Exception e)
            {
                File.WriteAllText($"ELog_{DateTime.Now:dd:MM:yyyy}.json", e.ToString());
            }
            finally
            {                
                Console.WriteLine($"[Logger] {jsonFileName} был изменен | {DateTime.Now:g}");
            }
        }
    }
}