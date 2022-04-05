using System.Windows;

namespace JocysCom.SslScanner.Tool
{
	partial class Icons_Default : ResourceDictionary
	{
		public Icons_Default()
		{
			InitializeComponent();
		}

		public static Icons_Default Current => _Current = _Current ?? new Icons_Default();
		private static Icons_Default _Current;

		public const string Icon_contact = nameof(Icon_contact);
		public const string Icon_earth_link = nameof(Icon_earth_link);
		public const string Icon_environment = nameof(Icon_environment);
		public const string Icon_environment_network = nameof(Icon_environment_network);
		public const string Icon_gearwheel = nameof(Icon_gearwheel);
		public const string Icon_lock = nameof(Icon_lock);
		public const string Icon_wax_seal = nameof(Icon_wax_seal);

	}
}
