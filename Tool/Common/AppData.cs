using JocysCom.ClassLibrary.ComponentModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace JocysCom.SslScanner.Tool
{
	public class AppData : JocysCom.ClassLibrary.Configuration.ISettingsItem, INotifyPropertyChanged
	{
		public bool Enabled { get; set; }

		public bool IsEmpty =>
			(Certificates?.Count ?? 0) == 0 &&
			(Domains?.Count ?? 0) == 0;

		public SortableBindingList<DataItem> Certificates
		{
			get => _Certificates = _Certificates ?? new SortableBindingList<DataItem>();
			set => _Certificates = value;
		}
		private SortableBindingList<DataItem> _Certificates;

		public SortableBindingList<DataItem> Domains
		{
			get => _Domains = _Domains ?? new SortableBindingList<DataItem>();
			set => _Domains = value;
		}
		private SortableBindingList<DataItem> _Domains;

		#region Whois

		public string WhoisValidFromRegex
		{
			get => _WhoisValidFromRegex;
			set => SetProperty(ref _WhoisValidFromRegex, value);
		}
		private string _WhoisValidFromRegex = @"Creation Date:\s*(?<Value>[^\s]+)";

		public string WhoisValidToRegex
		{
			get => _WhoisValidToRegex;
			set => SetProperty(ref _WhoisValidToRegex, value);
		}
		private string _WhoisValidToRegex = @"(Expiry|Expiration) Date:\s*(?<Value>[^\s]+)";

		#endregion

		#region ■ INotifyPropertyChanged

		public event PropertyChangedEventHandler PropertyChanged;

		protected void SetProperty<T>(ref T property, T value, [CallerMemberName] string propertyName = null)
		{
			property = value;
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		#endregion
	}
}
