using Eto.Forms;
using Eto.Drawing;
using System.Threading.Tasks;
using System;

namespace Forest
{
	public partial class MainForm : Form
	{
		public MainForm()
		{
			Title = "Forest";
			MinimumSize = new Size(500, 500);		

		    Load += MainForm_Load;
		}

        private async void MainForm_Load(object sender, EventArgs e)
        {
            await MainFormInitialization();
        }

        private async Task MainFormInitialization()
		{
			DirectoryService.FolderService.CreateAllFolders();
			EncryptionService.PhrasesGenerator.CreateMnemonicDictionary();
		}
	}
}
