using System;
using System.IO;

public class DirectoryService
{
    public class FileService
    {
        
    }
    public class FolderService
    {
        private readonly static string MainFolderPath = "MainFolder";
        private readonly static string[] MustHaveFoldersPath = { "UserInfo", "Contacts", "Settings", "Translations" };
        public static void CreateAllFolders()
        {
            try
            {
                if (!Directory.Exists(MainFolderPath))
                {
                    Directory.CreateDirectory(MainFolderPath);
                    foreach (var name in MustHaveFoldersPath)
                    {
                        if (!Directory.Exists(name))
                        {
                            Directory.CreateDirectory(MainFolderPath + "/" + name);
                        }
                    }
                }
                else
                {
                    foreach (var name in MustHaveFoldersPath)
                    {
                        if (!Directory.Exists(name))
                        {
                            Directory.CreateDirectory(MainFolderPath + "/" + name);
                        }
                    }
                }
            }
            catch(Exception e)
            {
                var logger = new ErrorManager();
                logger.LogError(e.ToString());
            }
        }
    }
}