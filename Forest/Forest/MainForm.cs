using Eto.Forms;
using Eto.Drawing;
using System.Collections.Generic;
using System;

namespace Forest
{
	public partial class MainForm : Form
	{
		public MainForm()
		{
			Title = "Forest";
			MinimumSize = new Size(500, 500);		

			MainFormInitialization();
		}
		private void MainFormInitialization()
		{
			DirectoryService.FolderService.CreateAllFolders();
			EncryptionService.PhrasesGenerator.CreateMnemonicDictionary();
		}
	}
}
