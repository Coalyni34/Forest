using System;
using System.IO;

public class DirectoryService
{
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
                    foreach(var name in MustHaveFoldersPath)
                    {
                        switch(name)
                        {
                            case "UserInfo":
                                var mFolders = new string[] { "ContactInfo", "Security" };
                                foreach(var f in mFolders)
                                {
                                    if(!Directory.Exists(f))
                                    {
                                        Directory.CreateDirectory($"{MainFolderPath}/{name}/{f}");
                                    }
                                }
                                break;
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
                            switch (name)
                            {
                                case "UserInfo":
                                    var mFolders = new string[] { "ContactInfo", "Security" };
                                    foreach (var f in mFolders)
                                    {
                                        if (!Directory.Exists(f))
                                        {
                                            Directory.CreateDirectory($"{MainFolderPath}/{name}/{f}");
                                        }
                                    }
                                    break;
                            }
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