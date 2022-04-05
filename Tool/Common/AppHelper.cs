using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Reflection;

namespace JocysCom.SslScanner.Tool
{
	public class AppHelper
	{

		public static void ImportFromHostsFile(IList<DataItem> list, string content)
		{
			var items = JocysCom.ClassLibrary.Network.HostsFileItem.ParseHosts(content, true);
			for (int i = 0; i < items.Count; i++)
			{
				var item = items[i];
				var oldItem = list.FirstOrDefault(x => string.Equals(x.Host, item.Host, StringComparison.InvariantCultureIgnoreCase));
				if (oldItem == null)
				{
					oldItem = new DataItem() { Host = item.Host, Port = 443, Environment = "Live", Group = "Web" };
					list.Add(oldItem);
				}
				if (item.Address != null)
				{
					if (item.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
						oldItem.IPv4 = $"{item.Address}";
					if (item.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
						oldItem.IPv6 = $"{item.Address}";
				}
				if (!string.IsNullOrWhiteSpace(item.Comment))
					oldItem.Notes = item.Comment;
			}
		}

		public static void ImportFromOtherList(IList<DataItem> list, IList<DataItem> source)
		{
			for (int i = 0; i < source.Count; i++)
			{
				var item = source[i];
				var oldItem = list.FirstOrDefault(x => string.Equals(x.Host, item.Host, StringComparison.InvariantCultureIgnoreCase));
				// Remove old item.
				if (oldItem != null)
					list.Remove(oldItem);
				// Add new item.
				list.Add(item);
			}
		}

		#region Convert Table To/From List

		/// <summary>
		/// Convert DataTable to List of objects. Can be used to convert DataTable to list of framework entities. 
		/// </summary>
		public static List<T> ConvertToList<T>(DataTable table)
		{
			if (table == null) return null;
			var list = new List<T>();
			var props = typeof(T).GetProperties();
			var columns = table.Columns.Cast<DataColumn>().ToArray();
			foreach (DataRow row in table.Rows)
			{
				var item = Convert<T>(row, props, columns);
				list.Add(item);
			}
			return list;
		}

		/// <summary>Convert DataRow to object.</summary>
		/// <param name="propsCache">Optional for cache reasons.</param>
		/// <param name="columnsCache">Optional for cache reasons.</param>
		public static T Convert<T>(DataRow row, PropertyInfo[] propsCache = null, DataColumn[] columnsCache = null)
		{
			var props = propsCache ?? typeof(T).GetProperties();
			var columns = columnsCache ?? row.Table.Columns.Cast<DataColumn>().ToArray();
			var item = Activator.CreateInstance<T>();
			foreach (var prop in props)
			{
				var column = columns.FirstOrDefault(x => prop.Name.Equals(x.ColumnName, StringComparison.OrdinalIgnoreCase));
				if (column == null)
					continue;
				if (!prop.CanWrite)
					continue;
				if (row.IsNull(column.ColumnName))
					continue;
				var value = row[column.ColumnName];
				// If type must be converted then...
				var columnType = row[column.ColumnName].GetType();
				if (columnType != prop.PropertyType)
				{
					// Get type if nullable.
					var underType = Nullable.GetUnderlyingType(prop.PropertyType);
					if (underType != null)
					{
						if (columnType == typeof(string) && Equals(value, ""))
							value = null;
					}
					var t = underType ?? prop.PropertyType;
					if (value != null)
						value = t.IsEnum
						? Enum.Parse(t, (string)value)
						: System.Convert.ChangeType(value, t);
				}
				prop.SetValue(item, value, null);
			}
			return item;
		}

		/// <summary>
		/// Convert List to DataTable. Can be used to pass data into stored procedures. 
		/// </summary>
		public static DataTable ConvertToTable<T>(IEnumerable<T> list)
		{
			if (list == null) return null;
			var table = new DataTable();
			var props = typeof(T).GetProperties().Where(x => x.CanRead).ToArray();
			foreach (var prop in props)
			{
				var underType = Nullable.GetUnderlyingType(prop.PropertyType);
				var columnType = underType ?? prop.PropertyType;
				table.Columns.Add(prop.Name, columnType);
			}
			var values = new object[props.Length];
			foreach (T item in list)
			{
				for (int i = 0; i < props.Length; i++)
					values[i] = props[i].GetValue(item, null);
				table.Rows.Add(values);
			}
			return table;
		}

		#endregion

	}
}
