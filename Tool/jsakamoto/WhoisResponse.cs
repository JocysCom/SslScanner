﻿using System;
using System.Linq;
using System.Text.RegularExpressions;
using NetTools;
#if !NETSTANDARD
using System.Runtime.Serialization;
#endif

namespace Whois.NET
{
#if NETSTANDARD
    [AttributeUsage(AttributeTargets.Class)]
    internal sealed class DataContractAttribute : Attribute
    {
        public DataContractAttribute() { }
    }
    [AttributeUsage(AttributeTargets.Property)]
    internal sealed class DataMemberAttribute : Attribute
    {
        public DataMemberAttribute() { }
    }
#endif

    /// <summary>
    /// A structure containing the whois response information.
    /// </summary>
    [DataContract]
    public class WhoisResponse
    {
        /// <summary>
        /// FQDN of WHOIS servers which sent query. The last element is the WHOIS server name that latest queried.
        /// </summary>
        [DataMember]
        public string[] RespondedServers { get; set; }

        [DataMember]
        public string Raw { get; set; }

        [DataMember]
        public string OrganizationName { get; set; }

        [DataMember]
        public IPAddressRange AddressRange { get; set; }

        /// <summary>
        /// A default constructor.
        /// </summary>
        public WhoisResponse()
        {
            this.RespondedServers = new string[0];
            this.Raw = "";
            this.OrganizationName = "";
        }

        /// <summary>
        /// A constructor that parses the provided response information.
        /// </summary>
        /// <param name="responsedServers">The servers that responded to the request.</param>
        /// <param name="rawWhoisResponse">The raw response from the last server.</param>
        public WhoisResponse(string[] responsedServers, string rawWhoisResponse)
        {
            this.RespondedServers = responsedServers;
            this.Raw = rawWhoisResponse;

            // resolve Organization Name.
            var m1 = Regex.Match(this.Raw,
                @"(^f\.\W*\[組織名\]\W+(?<orgName>[^\r\n]+))|" +
                @"(^\s*(OrgName|descr|Registrant Organization|owner):\W+(?<orgName>[^\r\n]+))",
                RegexOptions.Multiline);
            if (m1.Success)
            {
                this.OrganizationName = m1.Groups["orgName"].Value;
            }

            // resolve Address Range.
            var m2 = Regex.Match(this.Raw,
                @"(^a.\W*\[IPネットワークアドレス\]\W+(?<adr>[^\r\n]+))|" +
                @"(^(NetRange|CIDR|inetnum):\W+(?<adr>[^\r\n]+))",
                RegexOptions.Multiline);
            if (m2.Success)
            {
                this.AddressRange = IPAddressRange.Parse(m2.Groups["adr"].Value);
            }

            // resolve ARIN Address Range.
            if (responsedServers != null && responsedServers.Last() == "whois.arin.net")
            {
                var m3 = Regex.Matches(this.Raw,
                    @"(?<org>^.*) (?<adr>\d+\.\d+\.\d+\.\d+ - \d+\.\d+\.\d+\.\d+)",
                    RegexOptions.Multiline);
                if (m3.Count > 0)
                {
                    var mymatch = m3[m3.Count - 1];
                    // Test to see if the information was already picked up from above
                    if (mymatch.Groups["org"].Value.Trim() != "NetRange:" &&
                        mymatch.Groups["org"].Value.Trim() != "CIDR:" &&
                        mymatch.Groups["org"].Value.Trim() != "inetnum:")
                    {
                        this.AddressRange = IPAddressRange.Parse(mymatch.Groups["adr"].Value);
                        this.OrganizationName = mymatch.Groups["org"].Value.Trim();
                    }
                }
            }

        }
    }
}