using System.Collections.Generic;

namespace JocysCom.SslScanner.Tool
{
	public class ScriptExecutorParam
	{
		public IList<DataItem> Data { get; set; }
		public bool Cancel { get; set; }

		public DataItemType DataItemType { get; set; }	

	}
}
