using JocysCom.ClassLibrary.Controls;
using System.Reflection;
using System.Windows;
using System.IO;
using System;

namespace JocysCom.SslScanner.Tool
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{

		public MainWindow()
		{
			Current = this;
			ControlsHelper.InitInvokeContext();
			// Use configuration from local folder.
			var exeName = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
			var baseName = System.IO.Path.GetFileNameWithoutExtension(exeName);
			Global.AppData.XmlFile = new FileInfo($"{baseName}.xml");
			Global.AppData.Load();
			if (Global.AppData.Items.Count == 0)
			{
				Global.AppData.Items.Add(new AppData());
				Global.AppData.Save();
			}
			if (Global.AppSettings.Certificates.Count == 0)
				Global.AppSettings.Certificates.Add(new DataItem() { Host = "www.google.com", Port = 443 });
			if (Global.AppSettings.Domains.Count == 0)
				Global.AppSettings.Domains.Add(new DataItem() { Host = "google.com" });
			// Initialize.
			InitializeComponent();
			LoadHelpAndInfo();
		}

		public static MainWindow Current;

		void LoadHelpAndInfo()
		{
			var assembly = Assembly.GetExecutingAssembly();
			var ai = new ClassLibrary.Configuration.AssemblyInfo();
			Title = ai.GetTitle(true, false, true, false, false);
		}

		public InfoControl HMan;

		public static bool IsClosing;

		private void Window_Closed(object sender, EventArgs e)
		{
			Global.AppData.Save();
		}


		private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			IsClosing = true;
		}

		private void Window_Closed_1(object sender, EventArgs e)
		{

		}
	}

}
