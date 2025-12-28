using System;
using System.IO;

public class ErrorManager
{
    private string Name { set; get; } = "log_errors";
    public void LogError(string text)
    {
        var path = $"{Name}_{DateTime.Now}.txt";
        File.WriteAllText(path, text);
    }
}