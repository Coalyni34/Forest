using Eto.Forms;
using System.Threading.Tasks;
using System;
using static EncryptionService;
using ReusableTasks;

namespace Forest
{
	public partial class MainForm : Form
	{
		public MainForm()
		{
			var mainWindow = new IntefaceService.WindowInterfaceService.MainWindow();
			Title = mainWindow.Title;
			MinimumSize = mainWindow.MinimumSize;		
			Padding = mainWindow.Padding;		

			Content = mainWindow.MainLayout;

		    Load += MainForm_Load;		
		}

        private async void MainForm_Load(object sender, EventArgs e)
        {
            await MainFormInitialization();
        }

        private async Task MainFormInitialization()
        {
            FileInitialization();     
            //await Test();
        }   
        public async Task Test()
        {
            var bob = new Contact("Koya", false, IdGenerator.GeneratePublicUserId("Koya"));
            ContactService.ContactCreator.WriteContact(bob);
            var torrentService = new TorrentService("MainFolder/Contacts");
            await torrentService.CreateContactTorrentAsync($"MainFolder/Contacts/{bob.PublicId}/{bob.PublicId}.json", $"{bob.PublicId}", false);          
            await torrentService.StartContactTorrentAsync($"MainFolder/Contacts/{bob.PublicId}", $"{bob.PublicId}.torrent");
        }    

        private static void FileInitialization()
        {
            DirectoryService.CreateAllFolders();
            PhrasesGenerator.CreateMnemonicDictionary();
        }		
    }
}
