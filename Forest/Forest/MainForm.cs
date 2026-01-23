using Eto.Forms;
using Eto.Drawing;
using System.Threading.Tasks;
using System;
using System.IO;
using System.Text.Json;
using static EncryptionService;

namespace Forest
{
	public partial class MainForm : Form
	{
		public MainForm()
		{
			Title = "Forest";
			MinimumSize = new Size(700, 600);		
			Padding = new Padding(0);
			
			var leftPanel = new Panel();
			var middlePanel = new Panel();
			var mainPanel = new Panel();

			leftPanel.BackgroundColor = Color.FromArgb(40, 40, 40);
			leftPanel.MinimumSize = new Size(70, 0);
			leftPanel.Tag = "leftPanel";

			middlePanel.BackgroundColor = Color.FromArgb(50, 50, 50);
			middlePanel.MinimumSize = new Size(300, 0);
			middlePanel.Tag = "middlePanel";

			mainPanel.BackgroundColor = Color.FromArgb(30, 30, 30);
			mainPanel.Tag = "mainPanel";

			var mainLayout = new TableLayout
			{
				Spacing = new Size(0, 0),
				Padding = new Padding(0)				
			};

			mainLayout.Rows.Add(new TableRow(
				leftPanel,
				middlePanel,
				mainPanel
			));


			Content = mainLayout;

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
            DirectoryService.FolderService.CreateAllFolders();
            PhrasesGenerator.CreateMnemonicDictionary();
			var UserInfo = UserService.UserCreator.CreateUser("CoalyNi", true, "12345678");
			File.WriteAllText(UserService.UserInfoPath + "info.json", JsonSerializer.Serialize(UserInfo.contact));
        }		
    }
}
