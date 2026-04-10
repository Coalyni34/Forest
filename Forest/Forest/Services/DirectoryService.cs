using System;
using System.IO;

public class DirectoryService
{
    private readonly static string MainFolderPath = "MainFolder"; //Main Folder of the app for the working
    private readonly static string[] MustHaveFoldersPath = { "UserInfo", "Contacts", "Settings", "Translations", "Chats" }; //The list of the musthave folders
    public static void CreateAllFolders() //This method creates all folders, which the app needs to work 
    {
        try
        {
            if (!Directory.Exists(MainFolderPath)) //Checking that Main Folder exists (if not => creating one)
            {
                Directory.CreateDirectory(MainFolderPath); //Creating Main Folder
                foreach (var name in MustHaveFoldersPath) 
                {
                    if (!Directory.Exists(name)) //Checking that the musthave folders exists (if not => creating one)
                    {
                        Directory.CreateDirectory(MainFolderPath + "/" + name); //Creating the musthave folders
                    }
                }
                foreach (var name in MustHaveFoldersPath) 
                {
                    switch (name)
                    {
                        case "UserInfo":
                            var mFolders = new string[] { "ContactInfo", "Security" }; //The array of next folders
                            foreach (var f in mFolders)
                            {
                                if (!Directory.Exists(f)) //Checking that each folder exists (if not => creating one)
                                {
                                    Directory.CreateDirectory($"{MainFolderPath}/{name}/{f}");  //Creating folders
                                }
                            }
                            break;
                    }
                }
            }
            else
            {
                //This is just an another checkings
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
        catch (Exception e)
        {
            var logger = new ErrorManager();
            logger.LogError(e.ToString()); //Error logger
        }
    }
}