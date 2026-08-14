using System;
using System.IO;
using ForestMSG.Core.Services.FileSystem;

namespace ForestMSG.Core.ErrorManagement
{
    public class ErrorHandler
    {
        public static void LogError(string text)
        {
            var errorLogFolderName = $"Error_Log_{DateTime.Now:dd:MM:yyyy}";
            var errorLogFolderPath = Path.Combine(DirectoryNames.MainFolder, errorLogFolderName);

            var errorLogFileName = $"{errorLogFolderName}.txt";
            var errorLogFilePath = Path.Combine(errorLogFolderPath, errorLogFileName);

            if (!Directory.Exists(errorLogFolderName))
            {
                Directory.CreateDirectory(errorLogFolderName);
                Console.WriteLine($"[ErrorLogger] Created folder for error logs | DateTime: {DateTime.Now:g}");
            }

            if (!File.Exists(errorLogFileName))
            {
                File.WriteAllText(errorLogFilePath, text);
                Console.WriteLine($"[ErrorLogger] Created {errorLogFilePath} and writed first errol logs | DateTime: {DateTime.Now:g}");
            }
            else
            {
                var unitedText = File.ReadAllText(errorLogFilePath);
                File.WriteAllText(errorLogFilePath, unitedText);
                Console.WriteLine($"[ErrorLogger] Writed {errorLogFilePath} | DateTime: {DateTime.Now:g}");
            }
        }
    }
}