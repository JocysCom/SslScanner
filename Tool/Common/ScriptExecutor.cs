using JocysCom.ClassLibrary.Controls;
using System;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Policy;
using System.Text;
using System.Text.RegularExpressions;

namespace JocysCom.SslScanner.Tool
{

    public partial class ScriptExecutor : IProgress<ProgressEventArgs>
    {

        #region ■ IProgress

        public event EventHandler<ProgressEventArgs> Progress;

        public void Report(ProgressEventArgs e)
            => Progress?.Invoke(this, e);

        #endregion

        public void ProcessData(ScriptExecutorParam param)
        {
            try
            {
                var e = new ProgressEventArgs();
                // Create "References" solution folder.
                e.TopMessage = "Started...";
                e.State = ProgressStatus.Started;
                Report(e);
                var fromRx = new Regex(Global.AppSettings.WhoisValidFromRegex);
                var toRx = new Regex(Global.AppSettings.WhoisValidToRegex);
                for (var c = 0; c < param.Data.Count; c++)
                {
                    var item = param.Data[c];
                    e.State = ProgressStatus.Updated;
                    e.TopIndex = c;
                    e.TopCount = param.Data.Count;
                    e.TopData = item;
                    e.TopMessage = $"Host: {item.Host}";
                    e.ClearSub();
                    Report(e);
                    ControlsHelper.Invoke(() =>
                    {
                        item.StatusCode = System.Windows.MessageBoxImage.None;
                        item.StatusText = "Processing...";
                    });
                    var success = true;
                    e.SubMessage = "Get IP4 and IP6...";
                    Report(e);
                    var ip4 = Test_SSL_Support.GetHostAddresses(item.Host, System.Net.Sockets.AddressFamily.InterNetwork);
                    ControlsHelper.Invoke(() =>
                        item.IPv4 = ip4);
                    var ip6 = Test_SSL_Support.GetHostAddresses(item.Host, System.Net.Sockets.AddressFamily.InterNetworkV6);
                    ControlsHelper.Invoke(() =>
                        item.IPv6 = ip6);
                    if (param.DataItemType == DataItemType.Domains)
                    {
                        e.SubMessage = "Query Whois...";
                        Report(e);
                        var results = Whois.NET.WhoisClient.Query(item.Host)?.Raw;
                        item.WhoisData = results;
                        //var results = Whois2.Lookup(item.Host, whoisServer, Global.AppSettings.WhoisServerPort);
                        // Get From Date.
                        var match = fromRx.Match(results);
                        if (match.Success)
                        {
                            DateTime fromTime;
                            if (DateTime.TryParse(match.Groups["Value"].Value, out fromTime))
                                ControlsHelper.Invoke(() =>
                                    item.ValidFrom = fromTime);
                        }
                        else
                        {
                            success = false;
                        }
                        // Get To Date.
                        match = toRx.Match(results);
                        if (match.Success)
                        {
                            DateTime toTime;
                            if (DateTime.TryParse(match.Groups["Value"].Value, out toTime))
                                ControlsHelper.Invoke(() =>
                                    item.ValidTo = toTime);
                        }
                        else
                        {
                            success = false;
                        }
                    }
                    else if (param.DataItemType == DataItemType.Certificates)
                    {
                        e.SubMessage = "Test SSL/TLS...";
                        Report(e);
                        Test_SSL_Support.Progress = (string message) =>
                        {
                            e.SubMessage = message;
                            Report(e);
                        };
                        Test_SSL_Support.Results.Clear();
                        Test_SSL_Support.ProcessArguments(new[] { null, item.Host, item.Port.ToString() });
                        var results = Test_SSL_Support.Results;
                        var protocols = SslProtocols.None;
                        Test_SSL_Support.Result bestResult = null;
                        foreach (var result in results)
                        {
                            if (result.Success)
                            {
                                protocols |= result.Protocol;
                                bestResult = result;
                            }
                        }
                        if (bestResult != null)
                        {
                            var cert = bestResult.Certificate;
                            item.CN = cert.Subject;
                            item.ValidFrom = cert.NotBefore;
                            item.ValidTo = cert.NotAfter;
                            item.Algorithm = string.Format("{0}/{1}/{2}",
                                bestResult.ExchangeAlgorithm, bestResult.CipherAlgorithm, bestResult.HashAlgorithm);
                            // Get certificate.
                            var bytes = cert.Export(X509ContentType.Cert, (string)null);
                            var base64 = Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks);
                            var sb = new StringBuilder();
                            sb.AppendLine("-----BEGIN CERTIFICATE-----");
                            sb.AppendLine(base64);
                            sb.AppendLine("-----END CERTIFICATE-----");
                            item.PublicKeyData = sb.ToString();
                            item.SecurityProtocols = protocols;
                            var uri = new UriBuilder(Uri.UriSchemeHttps, item.Host, item.Port).Uri;
                            item.ResponseStatus = item.Port == 443
                                ? GetResponseStatus(uri.AbsoluteUri)
                                : "";
                        }
                        else
                        {
                            item.CN = null;
                            item.ValidFrom = null;
                            item.ValidTo = null;
                            item.Algorithm = null;
                            item.PublicKeyData = null;
                            item.SecurityProtocols = null;
                            success = false;
                        }
                    }
                    if (success)
                    {
                        ControlsHelper.Invoke(() =>
                        {
                            item.StatusCode = System.Windows.MessageBoxImage.Information;
                            item.StatusText = "Pass";
                        });
                    }
                    else
                    {
                        ControlsHelper.Invoke(() =>
                        {
                            item.StatusCode = System.Windows.MessageBoxImage.Warning;
                            item.StatusText = "Fail";
                        });
                    }
                }
                e = new ProgressEventArgs();
                e.State = ProgressStatus.Completed;
                Report(e);
            }
            catch (Exception ex)
            {
                var e2 = new ProgressEventArgs();
                e2.State = ProgressStatus.Exception;
                e2.Exception = ex;
                Report(e2);
            }
        }

        public static string GetResponseStatus(string url)
        {
            try
            {
                var request = (HttpWebRequest)WebRequest.Create(url);
                var response = (HttpWebResponse)request.GetResponse();
                var statusCode = (int)response.StatusCode;
                var statusText = response.StatusDescription;
                response.Close();
                return $"{statusCode} - {statusText}";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
    }

}

