using Eto.Forms;
using System.Threading.Tasks;
using System;
using static EncryptionService;

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
        }

        private static void FileInitialization()
        {
            DirectoryService.CreateAllFolders();
            PhrasesGenerator.CreateMnemonicDictionary();
        }		
    }
}
