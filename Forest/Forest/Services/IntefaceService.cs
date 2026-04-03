using Eto.Forms;
using Eto.Drawing;

public class IntefaceService
{
    public class ThemeService
    {
        public class Theme
        {
            
        }
        public class ThemeBuilder
        {
            
        }
    }
    public class WindowInterfaceService
    {
        public class MainWindow
        {
            public string Title = "Forest";
            public Size MinimumSize = new Size(700, 600);
            public Padding Padding = new Padding(0);
            public Panel LeftPanel = new Panel();
            public Panel MiddlePanel = new Panel();
            public Panel RightPanel = new Panel();
            public TableLayout MainLayout = new TableLayout();
            public Button SettingsButton = new Button();
            public Button AccounButton = new Button();
            public Button AddContactButton = new Button();

            public MainWindow()
            {
                LeftPanel.BackgroundColor = Color.FromArgb(40, 40, 40);
                LeftPanel.MinimumSize = new Size(70, 0);
                LeftPanel.Tag = "leftPanel";

                MiddlePanel.BackgroundColor = Color.FromArgb(50, 50, 50);
                MiddlePanel.MinimumSize = new Size(300, 0);
                MiddlePanel.Tag = "middlePanel";

                RightPanel.BackgroundColor = Color.FromArgb(30, 30, 30);
                RightPanel.Tag = "rightPanel";

                MainLayout = new TableLayout
                {
                    Spacing = new Size(0, 0),
                    Padding = new Padding(0)
                };

                MainLayout.Rows.Add(new TableRow(
                    LeftPanel,
                    MiddlePanel,
                    RightPanel
                ));
            }
        }
    }
}