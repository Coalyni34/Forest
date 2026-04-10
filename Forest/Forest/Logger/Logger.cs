using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

public class Logger
{
    private static readonly string LogsMainFolderPath = "MainFolder/Logs";
    public class Log
    {
        public string LogText { set; get; }
        public DateTime LogDateTime { set; get; }
        public Log() {}
        public Log(string LogText, DateTime LogDateTime)
        {
            this.LogText = LogText;
            this.LogDateTime = LogDateTime;
        }
    }
    public static void WriteLog(string LogText)
    {
        var folderPath = $"{LogsMainFolderPath}/forestMSG_log_{DateTime.Today}";

        if(!Directory.Exists(LogsMainFolderPath))
        {
            Directory.CreateDirectory(LogsMainFolderPath);            
        }
        if(!Directory.Exists(folderPath))
        {
            Directory.CreateDirectory(folderPath);
        }

        var todayLogs = new List<Log>();
        
        var jsonFileName = $"forestMSG_log_{DateTime.Today}.json";        

        var jsonFilePath = $"{folderPath}/{jsonFileName}";

        var textFileName = $"forestMSG_log_{DateTime.Today}.txt";

        var textFilePath = $"{folderPath}/{textFileName}";

        var textLogs = new List<string>();

        try
        {
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

           
            foreach (var t in todayLogs)
            {
                textLogs.Add($"Time: {t.LogDateTime}\nLog: {t.LogText}\n");
            }

            File.WriteAllText(jsonFilePath, jsonLog);
            File.WriteAllLines(textFilePath, textLogs);
        }       
        catch(Exception e)
        {
            ErrorManager errorManager = new ErrorManager();
            errorManager.LogError(e.Message);
        }
        finally
        {
            todayLogs.Clear();
            textLogs.Clear();
            Console.WriteLine($"{jsonFileName} has edited at {DateTime.Now}");
        }        
    }
}