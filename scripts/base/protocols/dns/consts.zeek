


module DNS;

export {
	const PTR = 12;
	const EDNS = 41;
	const NONE = 254;
	const ANY = 255;



	const query_types = {
		[1] = "A",
		[2] = "NS",
		[3] = "MD",
		[4] = "MF",
		[5] = "CNAME",
		[6] = "SOA",
		[7] = "MB",
		[8] = "MG",
		[9] = "MR",
		[10] = "NULL",
		[11] = "WKS",
		[12] = "PTR",
		[13] = "HINFO",
		[14] = "MINFO",
		[15] = "MX",
		[16] = "TXT",
		[17] = "RP",
		[18] = "AFSDB",
		[19] = "X25",
		[20] = "ISDN",
		[21] = "RT",
		[22] = "NSAP",
		[23] = "NSAP-PTR",
		[24] = "SIG",
		[25] = "KEY",
		[26] = "PX" ,
		[27] = "GPOS",
		[28] = "AAAA",
		[29] = "LOC",
		[30] = "NXT",
		[31] = "EID",
		[32] = "NIMLOC",
		[33] = "SRV",
		[34] = "ATMA",
		[35] = "NAPTR",
		[36] = "KX",
		[37] = "CERT",
		[38] = "A6",
		[39] = "DNAME",
		[40] = "SINK",
		[41] = "OPT",
		[42] = "APL",
		[43] = "DS",
		[44] = "SSHFP",
		[45] = "IPSECKEY",
		[46] = "RRSIG",
		[47] = "NSEC",
		[48] = "DNSKEY",
		[49] = "DHCID",
		[50] = "NSEC3",
		[51] = "NSEC3PARAM",
		[52] = "TLSA",
		[53] = "SMIMEA",
		[55] = "HIP",
		[56] = "NINFO",
		[57] = "RKEY",
		[58] = "TALINK",
		[59] = "CDS",
		[60] = "CDNSKEY",
		[61] = "OPENPGPKEY",
		[62] = "CSYNC",
		[63] = "ZONEMD",
		[64] = "SVCB",
		[65] = "HTTPS",
		[99] = "SPF",
		[100] = "UINFO",
		[101] = "UID",
		[102] = "GID",
		[103] = "UNSPEC",
		[104] = "NID",
		[105] = "L32",
		[106] = "L64",
		[107] = "LP",
		[108] = "EUI48",
		[109] = "EUI64",
		[249] = "TKEY",
		[250] = "TSIG",
		[251] = "IXFR",
		[252] = "AXFR",
		[253] = "MAILB",
		[254] = "MAILA",
		[255] = "*",
		[256] = "URI",
		[257] = "CAA",
		[32768] = "TA",
		[32769] = "DLV",
		[65281] = "WINS",
		[65282] = "WINS-R",
		[65422] = "XPF",
		[65521] = "INTEGRITY",
	} &default = function(n: count): string { return fmt("query-%d", n); };


	const base_errors = {
		[0] = "NOERROR",
		[1] = "FORMERR",
		[2] = "SERVFAIL",
		[3] = "NXDOMAIN",
		[4] = "NOTIMP",
		[5] = "REFUSED",
		[6] = "YXDOMAIN",
		[7] = "YXRRSET",
		[8] = "NXRRSet",
		[9] = "NOTAUTH",
		[10] = "NOTZONE",
		[11] = "unassigned-11",
		[12] = "unassigned-12",
		[13] = "unassigned-13",
		[14] = "unassigned-14",
		[15] = "unassigned-15",
		[16] = "BADVERS",
		[17] = "BADKEY",
		[18] = "BADTIME",
		[19] = "BADMODE",
		[20] = "BADNAME",
		[21] = "BADALG",
		[22] = "BADTRUNC",
		[23] = "BADCOOKIE",
		[3842] = "BADSIG",

	} &default = function(n: count): string { return fmt("rcode-%d", n); };


	const edns_zfield = {
		[0]     = "NOVALUE",
		[32768] = "DNS_SEC_OK",
	} &default="?";



	const classes = {
		[1]   = "C_INTERNET",
		[2]   = "C_CSNET",
		[3]   = "C_CHAOS",
		[4]   = "C_HESIOD",
		[254] = "C_NONE",
		[255] = "C_ANY",
	} &default = function(n: count): string { return fmt("qclass-%d", n); };


	const algorithms = {
		[0] = "reserved0",
		[1] = "RSA_MD5",
		[2] = "Diffie_Hellman",
		[3] = "DSA_SHA1",
		[4] = "Elliptic_Curve",
		[5] = "RSA_SHA1",
		[6] = "DSA_NSEC3_SHA1",
		[7] = "RSA_SHA1_NSEC3_SHA1",
		[8] = "RSA_SHA256",
		[10] = "RSA_SHA512",
		[12] = "GOST_R_34_10_2001",
		[13] = "ECDSA_curveP256withSHA256",
		[14] = "ECDSA_curveP384withSHA384",
		[15] = "Ed25519",
		[16] = "Ed448",
		[252] = "Indirect",
		[253] = "PrivateDNS",
		[254] = "PrivateOID",
		[255] = "reserved255",
	} &default = function(n: count): string { return fmt("algorithm-%d", n); };


	const digests = {
		[0] = "reserved0",
		[1] = "SHA1",
		[2] = "SHA256",
		[3] = "GOST_R_34_11_94",
		[4] = "SHA384",
	} &default = function(n: count): string { return fmt("digest-%d", n); };



	const svcparam_keys = {
		[0] = "mandatory",
		[1] = "alpn",
		[2] = "no-default-alpn",
		[3] = "port",
		[4] = "ipv4hint",
		[5] = "ech",
		[6] = "ipv6hint",
	} &default = function(n: count): string { return fmt("key-%d", n); };

	const DNS_OP_QUERY = 0;
	const DNS_OP_IQUERY = 1;
	const DNS_OP_SERVER_STATUS = 2;
	const DNS_OP_NOTIFY = 4;
	const DNS_OP_DYNAMIC_UPDATE = 5;
	const DNS_OP_DSO = 6;


	const opcodes = {
		[0] = "query",
		[1] = "iquery",
		[2] = "server-status",
		[4] = "notify",
		[5] = "dynamic-update",
		[6] = "dso",
	} &default = function(n: count): string { return fmt("opcode-%d", n); };




	const netbios_opcodes = {
		[0] = "netbios-query",
		[5] = "netbios-registration",
		[6] = "netbios-release",
		[7] = "netbios-wack",
		[8] = "netbios-refresh",
	} &default = function(n: count): string { return fmt("netbios-opcode-%d", n); };
}
