using JocysCom.ClassLibrary.Configuration;
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Xml.Serialization;

namespace JocysCom.SslScanner.Tool
{
	[Serializable]
	public class DataItem : ISettingsItem, INotifyPropertyChanged
	{

		[XmlIgnore]
		public bool IsChecked { get; set; }

		public string Environment { get => _Environment; set => SetProperty(ref _Environment, value); }
		string _Environment;


		public string Group { get => _Group; set => SetProperty(ref _Group, value); }
		string _Group;


		public string Host { get => _Host; set => SetProperty(ref _Host, value); }
		string _Host;


		public string IPv4 { get => _IPv4; set => SetProperty(ref _IPv4, value); }
		string _IPv4;


		public string IPv6 { get => _IPv6; set => SetProperty(ref _IPv6, value); }
		string _IPv6;

		public ushort Port { get => _Port; set => SetProperty(ref _Port, value); }
		ushort _Port;

		public bool? IsValid { get => _IsValid; set => SetProperty(ref _IsValid, value); }
		bool? _IsValid;

		[XmlIgnore] 
		public bool IsValidSpecified => IsValid.HasValue;

		public string PublicKeyData { get => _PublicKeyData; set => SetProperty(ref _PublicKeyData, value); }
		string _PublicKeyData;

		public string WhoisData { get => _WhoisData; set => SetProperty(ref _WhoisData, value); }
		string _WhoisData;

		public int? Bits { get => _Bits; set => SetProperty(ref _Bits, value); }
		int? _Bits;

		[XmlIgnore]
		public bool BitsSpecified => Bits.HasValue;

		public SslProtocols? SecurityProtocols
		{
			get => _SecurityProtocols;
			set
			{
				SetProperty(ref _SecurityProtocols, value);
				OnPropertyChanged(nameof(SupportSsl3));
				OnPropertyChanged(nameof(SupportTls));
				OnPropertyChanged(nameof(SupportTls11));
				OnPropertyChanged(nameof(SupportTls12));
				OnPropertyChanged(nameof(SupportTls13));
			}
		}
		System.Security.Authentication.SslProtocols? _SecurityProtocols;

		[XmlIgnore]
		public bool SecurityProtocolsSpecified => SecurityProtocols.HasValue;

		[XmlIgnore]
		public bool? SupportSsl3
#pragma warning disable CS0618 // Type or member is obsolete
			=> SecurityProtocols?.HasFlag(SslProtocols.Ssl3);
#pragma warning restore CS0618 // Type or member is obsolete

		[XmlIgnore]
		public bool? SupportTls
			=> SecurityProtocols?.HasFlag(SslProtocols.Tls);

		[XmlIgnore]
		public bool? SupportTls11
			=> SecurityProtocols?.HasFlag(SslProtocols.Tls11);

		[XmlIgnore]
		public bool? SupportTls12
			=> SecurityProtocols?.HasFlag(SslProtocols.Tls12);
		
		[XmlIgnore]
		public bool? SupportTls13
			=> SecurityProtocols?.HasFlag(SslProtocols.Tls13);
		
		public string Algorithm
		{
			get => _Algorithm;
			set => SetProperty(ref _Algorithm, value);
		}
		string _Algorithm;

		public DateTime? ValidFrom { get => _ValidFrom; set => SetProperty(ref _ValidFrom, value); }
		DateTime? _ValidFrom;

		[XmlIgnore]
		public bool ValidFromSpecified => ValidFrom.HasValue;

		public DateTime? ValidTo { get => _ValidTo; set { SetProperty(ref _ValidTo, value); OnPropertyChanged(nameof(ValidDays)); }  }
		DateTime? _ValidTo;

		[XmlIgnore]
		public bool ValidToSpecified => ValidTo.HasValue;

		public int? ValidDays
			=> ValidTo.HasValue ? (int?)ValidTo.Value.Subtract(DateTime.Now).TotalDays : null;

		[XmlIgnore]
		public bool ValidDaysSpecified => ValidDays.HasValue;



		public string CN { get => _CN; set => SetProperty(ref _CN, value); }
		string _CN;

		public string SAN { get => _SAN; set => SetProperty(ref _SAN, value); }
		string _SAN;

		public string Notes { get => _Notes; set => SetProperty(ref _Notes, value); }
		string _Notes;

		public string HelpLink { get => _HelpLink; set => SetProperty(ref _HelpLink, value); }
		string _HelpLink;

		public DateTime Date { get => _Date; set => SetProperty(ref _Date, value); }
		DateTime _Date;

		public bool IsActive { get => _IsActive; set => SetProperty(ref _IsActive, value); }
		bool _IsActive;

		public bool IsSame(DataItem item)
		{
			return
			item.Host == Host;
		}

		public System.Windows.MessageBoxImage StatusCode { get => _StatusCode; set => SetProperty(ref _StatusCode, value); }
		System.Windows.MessageBoxImage _StatusCode;

		public string StatusText { get => _StatusText; set => SetProperty(ref _StatusText, value); }
		string _StatusText;


		#region ■ ISettingsItem

		bool ISettingsItem.Enabled { get => IsEnabled; set => IsEnabled = value; }
		private bool IsEnabled;

		public bool IsEmpty =>
			string.IsNullOrEmpty(Host);

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
