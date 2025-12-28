using System;
using System.IO;

public class ErrorManager
{
    private string Name { set; get; } = "log_errors";
    public void LogError(string text)
    {
        var path = $"{Name}_{DateTime.Now}.txt";
        if(!File.Exists(path))
        {
            File.WriteAllText(path, text);
        }
        else
        {
            var oldText = File.ReadAllText(path);
            var newText = oldText + "\n" + text;
            File.WriteAllText(path, newText);
        }        
    }
}