using JocysCom.ClassLibrary.ComponentModel;
using JocysCom.ClassLibrary.Configuration;
using JocysCom.ClassLibrary.Controls;
using JocysCom.ClassLibrary.Controls.Themes;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace JocysCom.SslScanner.Tool.Controls
{
	/// <summary>
	/// Interaction logic for DataListControl.xaml
	/// </summary>
	public partial class DataListControl : UserControl
	{
		public DataListControl()
		{
			InitializeComponent();
			ProgressPanel.UpdateProgress();
			if (ControlsHelper.IsDesignMode(this))
				return;
			var dataItems = new SortableBindingList<DataItem>();
			SetDataItems(dataItems);
			// Configure converter.
			var gridFormattingConverter = MainDataGrid.Resources.Values.OfType<ItemFormattingConverter>().First();
			gridFormattingConverter.ConvertFunction = _MainDataGridFormattingConverter_Convert;
		}

		object _MainDataGridFormattingConverter_Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
		{
			var sender = (FrameworkElement)values[0];
			var template = (FrameworkElement)values[1];
			var cell = (DataGridCell)(template ?? sender).Parent;
			var value = values[2];
			var item = (DataItem)cell.DataContext;
			// Format StatusCodeColumn value.
			if (cell.Column == StatusCodeColumn)
			{
				switch (item.StatusCode)
				{
					case MessageBoxImage.Error:
						return Icons.Current[Icons.Icon_Error];
					case MessageBoxImage.Question:
						return Icons.Current[Icons.Icon_Question];
					case MessageBoxImage.Warning:
						return Icons.Current[Icons.Icon_Warning];
					case MessageBoxImage.Information:
						return Icons.Current[Icons.Icon_OK];
					default:
						return Icons.Current[Icons.Icon_InformationGrey];
				}
			}
			if (cell.Column == ValidDaysColumn)
			{
				var date = item.ValidTo ?? new DateTime();
				var daysLeft = date.Subtract(DateTime.Now).TotalDays;
				Style cellStyle = null;
				if (item.ValidDays.HasValue)
				{
					cellStyle = (Style)App.Current.Resources["DataGridCell_D120"];
					if (daysLeft < 90) cellStyle = (Style)App.Current.Resources["DataGridCell_D060"];
					if (daysLeft < 30) cellStyle = (Style)App.Current.Resources["DataGridCell_D030"];
					if (daysLeft < 0) cellStyle = (Style)App.Current.Resources["DataGridCell_D000"];
				}
				cell.Style = cellStyle;
				return $"{item.ValidDays}";
			}

			if (cell.Column == IsActiveImageColumn)
			{
				return item.IsActive ? Icons_Default.Current[Icons_Default.Icon_environment_network] : null;
			}
			if (cell.Column == IsActiveColumn)
			{
				cell.Opacity = 0.5;
				return item.IsActive ? "Active" : "";
			}
			if (cell.Column == DateColumn)
			{
				value = string.Format("{0:HH:mm:ss:fff}", item.Date);
				cell.Opacity = 0.5;
			}
			// Other.
			return value;
		}

		public void SetDataItems(SortableBindingList<DataItem> dataItems)
		{
			if (DataItems != null)
			{
				DataItems.ListChanged -= DataItems_ListChanged;
				MainDataGrid.SelectionChanged -= MainDataGrid_SelectionChanged;
			}
			DataItems = dataItems;
			DataItems.ListChanged += DataItems_ListChanged;
			MainDataGrid.SelectionChanged += MainDataGrid_SelectionChanged;
			MainDataGrid.ItemsSource = dataItems;
			UpdateControlsFromList();
			if (DataItems.Count > 0)
				MainDataGrid.SelectedIndex = 0;
		}

		private void MainDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			UpdateControlsFromList();
		}

		public List<DataItem> GetCheckedOrSelectedItems(out bool containsChecked)
		{
			containsChecked = DataItems.Any(x => x.IsChecked);
			var items = containsChecked
				? DataItems.Where(x => x.IsChecked).ToList()
				: MainDataGrid.SelectedItems.Cast<DataItem>().ToList();
			return items;
		}


		bool selectionsUpdating = false;
		private void DataItems_ListChanged(object sender, ListChangedEventArgs e)
		{
			ControlsHelper.BeginInvoke(() =>
			{
				if (e.ListChangedType == ListChangedType.ItemChanged)
				{
					if (!selectionsUpdating && e.PropertyDescriptor?.Name == nameof(DataItem.IsChecked))
					{
						selectionsUpdating = true;
						var selectedItems = MainDataGrid.SelectedItems.Cast<DataItem>().ToList();
						// Get updated item.
						var item = (DataItem)MainDataGrid.Items[e.NewIndex];
						if (selectedItems.Contains(item))
						{
							// Update other items to same value.
							selectedItems.Remove(item);
							foreach (var selecetdItem in selectedItems)
								if (selecetdItem.IsChecked != item.IsChecked)
									selecetdItem.IsChecked = item.IsChecked;
						}
						selectionsUpdating = false;
					}
				}
				else if (e.ListChangedType == ListChangedType.ItemAdded || e.ListChangedType == ListChangedType.ItemDeleted)
				{
					UpdateControlsFromList();
				}
			});
		}



		public SortableBindingList<DataItem> DataItems { get; set; } = new SortableBindingList<DataItem>();

		private void DeleteButton_Click(object sender, RoutedEventArgs e)
		{
			var items = GetCheckedOrSelectedItems(out bool containsChecked);
			// Return if nothing to delete.
			if (items.Count == 0)
				return;
			var message = string.Format("Are you sure you want to delete {0} item{1}?",
					items.Count, items.Count == 1 ? "" : "s");
			var form = new MessageBoxWindow();
			var result = form.ShowDialog(message, "Delete", MessageBoxButton.YesNo, MessageBoxImage.Question);
			if (result != MessageBoxResult.Yes)
				return;
			foreach (var item in items)
				DataItems.Remove(item);
		}

		private void AddButton_Click(object sender, RoutedEventArgs e)
		{
			var box = new JocysCom.ClassLibrary.Controls.MessageBoxWindow();
			box.SetSize(640, 240);
			var results = box.ShowPrompt("", "Add Hosts");
			if (results != MessageBoxResult.OK)
				return;
			var value = box.MessageTextBox.Text;
			AppHelper.ImportFromHostsFile(DataItems, value);
		}

		private void CertificateButton_Click(object sender, RoutedEventArgs e)
		{
			var item = MainDataGrid.SelectedItems.Cast<DataItem>().FirstOrDefault();
			var data = item?.PublicKeyData;
			if (string.IsNullOrEmpty(data))
				return;
			var bytes = System.Text.Encoding.UTF8.GetBytes(data);
			var fi = SettingsHelper.SaveFileWithChecksum($"{item.Host}.PublicKey.cer", bytes);
			ControlsHelper.OpenPath(fi.FullName);
		}

		private void WhoisButton_Click(object sender, RoutedEventArgs e)
		{
			var item = MainDataGrid.SelectedItems.Cast<DataItem>().FirstOrDefault();
			var data = item?.WhoisData;
			if (string.IsNullOrEmpty(data))
				return;
			var bytes = System.Text.Encoding.UTF8.GetBytes(data);
			var fi = SettingsHelper.SaveFileWithChecksum($"{item.Host}.Whois.txt", bytes);
			ControlsHelper.OpenPath(fi.FullName);
		}

		private void WebButton_Click(object sender, RoutedEventArgs e)
		{
			var item = MainDataGrid.SelectedItems.Cast<DataItem>().FirstOrDefault();
			var data = item.Host;
			if (string.IsNullOrEmpty(data))
				return;
			var uri = $"https://{item.Host}";
			if (item.Port != 443 && item.Port != 0)
				uri += $":{item.Port}";
			ControlsHelper.OpenPath(uri);
		}

		private void WebTestButton_Click(object sender, RoutedEventArgs e)
		{
		}

		private void SslTestButton_Click(object sender, RoutedEventArgs e)
		{
		}

		#region ■ Properties

		[Category("Main"), DefaultValue(DataItemType.None)]
		public DataItemType DataType
		{
			get => _DataType;
			set { _DataType = value; UpdateType(); }
		}
		private DataItemType _DataType;

		void UpdateType()
		{
			switch (DataType)
			{
				case DataItemType.Certificates:
					EndColumn.Width = new DataGridLength(1, DataGridLengthUnitType.Star);
					ShowColumns(StatusCodeColumn, StatusTextColumn,
						GroupColumn, EnvironmentColumn,
						HostColumn, PortColumn, IPv4Column,
						ValidToColumn, ValidDaysColumn,
						ProtocolsColumn, AlgorithmColumn,
						NotesColumn, EndColumn);
					ShowButtons(AddButton, ImportButton, ExportButton,
						CertificateButton, WebButton,
						DeleteButton, RefreshButton, RefreshAllButton);
					if (!ControlsHelper.IsDesignMode(this))
						SetDataItems(Global.AppSettings.Certificates);
					break;
				case DataItemType.Domains:
					EndColumn.Width = new DataGridLength(1, DataGridLengthUnitType.Star);
					ShowColumns(StatusCodeColumn, StatusTextColumn,
						GroupColumn, EnvironmentColumn,
						HostColumn, IPv4Column,
						ValidToColumn, ValidDaysColumn,
						NotesColumn, EndColumn);
					ShowButtons(AddButton, ImportButton, ExportButton,
						WhoisButton, WebButton,
						DeleteButton, RefreshButton, RefreshAllButton);
					if (!ControlsHelper.IsDesignMode(this))
						SetDataItems(Global.AppSettings.Domains);
					break;
				default:
					break;
			}
			UpdateControlsFromList();
		}

		public void ShowColumns(params DataGridColumn[] args)
		{
			var all = MainDataGrid.Columns.ToArray();
			foreach (var control in all)
				control.Visibility = args.Contains(control) ? Visibility.Visible : Visibility.Collapsed;
		}

		public void ShowButtons(params Button[] args)
		{
			var all = ControlsHelper.GetAll<Button>(LeftToolBar).ToList();
			all.AddRange(ControlsHelper.GetAll<Button>(RightToolBar));
			foreach (var control in all)
				control.Visibility = args.Contains(control) ? Visibility.Visible : Visibility.Collapsed;
		}

		void UpdateControlsFromList()
		{
			var item = MainDataGrid.SelectedItems.Cast<DataItem>().FirstOrDefault();
			// Button: Whois.
			WhoisButton.IsEnabled = !string.IsNullOrEmpty(item?.WhoisData);
			// Button: Certificate.
			CertificateButton.IsEnabled = !string.IsNullOrEmpty(item?.PublicKeyData);
			// Button: Refresh.
			var items = GetCheckedOrSelectedItems(out var containsChecked);
			RefreshButton.IsEnabled = items.Count > 0;
			RefreshButtonLabel.Content = $"Refresh [{items.Count}]";
		}

		#endregion

		private void RefreshButton_Click(object sender, RoutedEventArgs e)
		{
			var items = GetCheckedOrSelectedItems(out var containsSelected);
			Refresh(items);
		}

		private void RefreshAllButton_Click(object sender, RoutedEventArgs e)
		{
			Refresh(DataItems);
		}

		private void Refresh(IList<DataItem> items)
		{
			InfoPanel.AddTask(DataType);
			_ScriptExecutorParam = new ScriptExecutorParam();
			_ScriptExecutorParam.Data = items;
			_ScriptExecutorParam.DataItemType = DataType;
			var success = System.Threading.ThreadPool.QueueUserWorkItem(ExecuteTask, _ScriptExecutorParam);
			if (!success)
			{
				ProgressPanel.UpdateProgress("Task failed!", "", true);
				InfoPanel.RemoveTask(DataType);
			}
		}

		ScriptExecutor _ScriptExecutor;
		ScriptExecutorParam _ScriptExecutorParam;

		InfoControl InfoPanel
			=> MainWindow.Current.InfoPanel;

		void ExecuteTask(object state)
		{
			ControlsHelper.Invoke(() =>
				ProgressPanel.UpdateProgress("Starting...", "", true));
			_ScriptExecutor = new ScriptExecutor();
			_ScriptExecutor.Progress -= _ScriptExecutor_Progress;
			_ScriptExecutor.Progress += _ScriptExecutor_Progress;
			_ScriptExecutor.ProcessData((ScriptExecutorParam)state);
		}

		private void _ScriptExecutor_Progress(object sender, ProgressEventArgs e)
		{
			if (ControlsHelper.InvokeRequired)
			{
				ControlsHelper.Invoke(() =>
					_ScriptExecutor_Progress(sender, e));
				return;
			}
			var scanner = (ScriptExecutor)sender;
			switch (e.State)
			{
				case ProgressStatus.Started:
					var sm = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - Started...";
					ProgressPanel.UpdateProgress(sm, "");
					break;
				case ProgressStatus.Updated:
					ProgressPanel.UpdateProgress(e);
					break;
				case ProgressStatus.Exception:
					MessageBox.Show($"{e.Exception.ToString()}");
					InfoPanel.RemoveTask(DataType);
					break;
				case ProgressStatus.Completed:
					var dm = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - Done.";
					ProgressPanel.UpdateProgress();
					InfoPanel.RemoveTask(DataType);
					UpdateControlsFromList();
					break;
				default:
					break;
			}
		}

		#region Export/ Import

		System.Windows.Forms.OpenFileDialog ImportOpenFileDialog { get; } = new System.Windows.Forms.OpenFileDialog();

		private void ImportButton_Click(object sender, RoutedEventArgs e)
		{
			var dialog = ImportOpenFileDialog;
			dialog.SupportMultiDottedExtensions = true;
			dialog.DefaultExt = "*.csv";
			dialog.Filter = "CSV Data (*.csv)|*.csv|JSON Data (*.json)|*.json|XML Data (*.XML)|*.xml|All files (*.*)|*.*";
			dialog.FilterIndex = 1;
			dialog.RestoreDirectory = true;
			//var fi = Data.XmlFile;
			//if (string.IsNullOrEmpty(dialog.FileName))
			//	dialog.FileName = System.IO.Path.GetFileNameWithoutExtension(fi.Name);
			//if (string.IsNullOrEmpty(dialog.InitialDirectory))
			//	dialog.InitialDirectory = fi.Directory.FullName;
			dialog.Title = "Import Data File";
			var result = dialog.ShowDialog();
			if (result != System.Windows.Forms.DialogResult.OK)
				return;
			var fi = new FileInfo(dialog.FileName);
			var content = System.IO.File.ReadAllText(fi.FullName);
			List<DataItem> data;
			switch (fi.Extension.ToUpper())
			{
				case ".JSON":
					data = JocysCom.ClassLibrary.Runtime.Serializer.DeserializeFromJson<List<DataItem>>(content);
					break;
				case ".XML":
					data = JocysCom.ClassLibrary.Runtime.Serializer.DeserializeFromXmlString<List<DataItem>>(content);
					break;
				default:
					// Import as CSV.
					var table = ClassLibrary.Files.CsvHelper.Read(fi.FullName, true);
					data = AppHelper.ConvertToList<DataItem>(table);
					break;
			}
			AppHelper.ImportFromOtherList(DataItems, data);
		}

		System.Windows.Forms.SaveFileDialog ExportSaveFileDialog { get; } = new System.Windows.Forms.SaveFileDialog();

		private void ExportButton_Click(object sender, RoutedEventArgs e)
		{
			var dialog = ExportSaveFileDialog;
			dialog.DefaultExt = "*.csv";
			dialog.Filter = "CSV Data (*.csv)|*.csv|JSON Data (*.json)|*.json|XML Data (*.XML)|*.xml|All files (*.*)|*.*";
			dialog.FilterIndex = 1;
			dialog.RestoreDirectory = true;
			if (string.IsNullOrEmpty(dialog.FileName))
				dialog.FileName = $"{DataType}_{DateTime.Now:yyyyMMdd}";
			//if (string.IsNullOrEmpty(dialog.InitialDirectory)) dialog.InitialDirectory = ;
			dialog.Title = "Export Data File";
			var result = dialog.ShowDialog();
			if (result != System.Windows.Forms.DialogResult.OK)
				return;
			var fi = new FileInfo(dialog.FileName);
			string content;
			switch (fi.Extension.ToUpper())
			{
				case ".JSON":
					content = JocysCom.ClassLibrary.Runtime.Serializer.SerializeToJson(DataItems);
					break;
				case ".XML":
					content = JocysCom.ClassLibrary.Runtime.Serializer.SerializeToXmlString(DataItems);
					break;
				default:
					// Export as CSV.
					var table = AppHelper.ConvertToTable(DataItems);
					content = JocysCom.ClassLibrary.Files.CsvHelper.Write(table);
					break;
			}
			var bytes = System.Text.Encoding.UTF8.GetBytes(content);
			SettingsHelper.WriteIfDifferent(dialog.FileName, bytes);
		}

		#endregion


	}

}