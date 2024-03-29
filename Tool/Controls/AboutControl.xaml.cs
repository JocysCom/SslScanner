﻿using JocysCom.ClassLibrary.Configuration;
using JocysCom.ClassLibrary.Controls;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;

namespace JocysCom.SslScanner.Tool.Controls
{
	/// <summary>
	/// Interaction logic for AboutControl.xaml
	/// </summary>
	public partial class AboutControl : UserControl
	{
		public AboutControl()
		{
			InitHelper.InitTimer(this, InitializeComponent);
		}

		private void HyperLink_RequestNavigate(object sender, RequestNavigateEventArgs e)
		{
			ControlsHelper.OpenPath(e.Uri.AbsoluteUri);
		}

		private void UserControl_Loaded(object sender, RoutedEventArgs e)
		{
			if (ControlsHelper.IsDesignMode(this))
				return;
			var ai = new AssemblyInfo();
			ChangeLogTextBox.Text = ClassLibrary.Helper.FindResource<string>("Documents.ChangeLog.txt", ai.Assembly);
			AboutProductLabel.Content = string.Format("{0} {1} {2}", ai.Company, ai.Product, ai.Version);
			AboutDescriptionLabel.Content = ai.Description;
			LicenseTextBox.Text = ClassLibrary.Helper.FindResource<string>("Documents.License.txt", ai.Assembly);
			LicenseTabPage.Header = string.Format("{0} {1} License", ai.Product, ai.Version.ToString(2));
		}
	}
}
