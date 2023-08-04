using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;

namespace JocysCom.ClassLibrary.Network
{

	public class HostsFileItem
	{
		public HostsFileItem(string host = null, IPAddress address = null, string comment = null)
		{
			Host = host;
			Address = address;
			Comment = comment;
		}

		public bool IsEnabled { get; set; }

		public string Host { get; set; }

		public IPAddress Address { get; set; }

		public string Comment { get; set; }

		#region Helper Functions

		private static Regex _HostsRegex = new Regex(@"^#?\s*"
				+ @"(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-f:]+)\s+"
				+ @"(?<hosts>(([a-z0-9][-_a-z0-9]*\.?)+\s*)+)"
				+ @"(?:#\s*(?<comment>.*?)\s*)?$",
				RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

		private static Regex _HostsNoAddressRegex = new Regex(@"^#?\s*"
			+ @"(?:(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-f:]+)\s+)?"
			+ @"(?<hosts>(([a-z0-9][-_a-z0-9]*\.?)+\s*)+)"
			+ @"(?:#\s*(?<comment>.*?)\s*)?$",
		RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

		/// <summary>
		/// Parse the hosts file content.
		/// </summary>
		/// <param name="content">Content of hosts file.</param>
		/// <param name="allowNoAddress">True - allow list of host names witout IP addresses. Default: False.</param>
		public static List<HostsFileItem> ParseHosts(string content, bool allowNoAddress = false)
		{
			var result = new List<HostsFileItem>();
			var lines = content.Split(new string[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
			for (int i = 0; i < lines.Length; i++)
			{
				var line = lines[i].Trim();
				// If line is empty then skip.
				if (string.IsNullOrWhiteSpace(line))
					continue;
				var match = allowNoAddress
					? _HostsNoAddressRegex.Match(line)
					: _HostsRegex.Match(line);
				if (!match.Success)
					continue;
				var enabled = line[0] != '#';
				var address = match.Groups["ip"].Value.Trim();
				var hosts = match.Groups["hosts"].Value.Trim().Split(" ".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
				var comment = match.Groups["comment"].Value.Trim();
				// Skip invalid IP address
				IPAddress ipAddress;
				if (!IPAddress.TryParse(address, out ipAddress) && !allowNoAddress)
					continue;
				// If comment was hidden then...
				if (comment.StartsWith("!"))
					comment = comment.Substring(1).Trim();
				foreach (var host in hosts)
				{
					var entry = new HostsFileItem(host, ipAddress, comment);
					entry.IsEnabled = enabled;
					result.Add(entry);
				}
			}
			return result;
		}

		#endregion

	}
}
