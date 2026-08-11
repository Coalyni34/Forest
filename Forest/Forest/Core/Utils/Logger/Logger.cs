using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using ForestMSG.Core.ErrorManagement;
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
            var folderPath = Path.Combine(DirectoryNames.MainFolder, $"{DateTime.Today}");
            if (!Directory.Exists(folderPath))
            {
                Directory.CreateDirectory(folderPath);
                Console.WriteLine($"[Logger] Folder {folderPath} has created");
            }
           
            var jsonFileName = $"Log_{DateTime.Today}.json";
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
                ErrorHandler errorManager = new ErrorHandler();
                errorManager.LogError(e.Message);
            }
            finally
            {                
                Console.WriteLine($"[Logger] {jsonFileName} has edited at {DateTime.Now}");
            }
        }
    }
}