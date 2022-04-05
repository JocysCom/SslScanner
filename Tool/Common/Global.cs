using System.Linq;

namespace JocysCom.SslScanner.Tool
{
	public static class Global
	{
		public static AppData AppSettings =>
			AppData.Items.FirstOrDefault();

		public static ClassLibrary.Configuration.SettingsData<AppData> AppData =
			new ClassLibrary.Configuration.SettingsData<AppData>(null, false, null, System.Reflection.Assembly.GetExecutingAssembly());

	}
}
