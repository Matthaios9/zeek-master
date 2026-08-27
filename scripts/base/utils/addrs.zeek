

module GLOBAL;

export {



	const ipv4_decim = /[0-9]{1}|[0-9]{2}|0[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]/;

	const ipv4_addr_regex = ipv4_decim & /\./ & ipv4_decim & /\./ & ipv4_decim & /\./ & ipv4_decim;

	const ipv6_hextet = /[0-9A-Fa-f]{1,4}/;

	const ipv6_8hex_regex = /([0-9A-Fa-f]{1,4}:){7}/ & ipv6_hextet;

	const ipv6_hex4dec_regex = /([0-9A-Fa-f]{1,4}:){6}/ & ipv4_addr_regex;

	const ipv6_compressed_lead_hextets0 = /::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,6})?/;

	const ipv6_compressed_lead_hextets1 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,5})?/;

	const ipv6_compressed_lead_hextets2 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){1}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,4})?/;

	const ipv6_compressed_lead_hextets3 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){2}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,3})?/;

	const ipv6_compressed_lead_hextets4 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){3}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,2})?/;

	const ipv6_compressed_lead_hextets5 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){4}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,1})?/;

	const ipv6_compressed_lead_hextets6 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){5}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,0})?/;

	const ipv6_compressed_lead_hextets7 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){6}::/;

	const ipv6_compressed_hex_regex = ipv6_compressed_lead_hextets0 |
	                                  ipv6_compressed_lead_hextets1 |
	                                  ipv6_compressed_lead_hextets2 |
	                                  ipv6_compressed_lead_hextets3 |
	                                  ipv6_compressed_lead_hextets4 |
	                                  ipv6_compressed_lead_hextets5 |
	                                  ipv6_compressed_lead_hextets6 |
	                                  ipv6_compressed_lead_hextets7;

	const ipv6_compressed_hext4dec_lead_hextets0 = /::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,4})?/ & ipv4_addr_regex;

	const ipv6_compressed_hext4dec_lead_hextets1 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,3})?/ & ipv4_addr_regex;

	const ipv6_compressed_hext4dec_lead_hextets2 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){1}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,2})?/ & ipv4_addr_regex;

	const ipv6_compressed_hext4dec_lead_hextets3 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){2}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,1})?/ & ipv4_addr_regex;

	const ipv6_compressed_hext4dec_lead_hextets4 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){3}::([0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,0})?/ & ipv4_addr_regex;

	const ipv6_compressed_hext4dec_lead_hextets5 = /[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){4}::/ & ipv4_addr_regex;

	const ipv6_compressed_hex4dec_regex = ipv6_compressed_hext4dec_lead_hextets0 |
	                                      ipv6_compressed_hext4dec_lead_hextets1 |
	                                      ipv6_compressed_hext4dec_lead_hextets2 |
	                                      ipv6_compressed_hext4dec_lead_hextets3 |
	                                      ipv6_compressed_hext4dec_lead_hextets4 |
	                                      ipv6_compressed_hext4dec_lead_hextets5;

	const ipv6_addr_regex = ipv6_8hex_regex |
	                        ipv6_compressed_hex_regex |
	                        ipv6_hex4dec_regex |
	                        ipv6_compressed_hex4dec_regex;

	const ip_addr_regex = ipv4_addr_regex | ipv6_addr_regex;






	global has_valid_octets: function(octets: string_vec): bool;








	global extract_ip_addresses: function(input: string, check_wrapping: bool &default=F): string_vec;









	global addr_to_uri: function(a: addr): string;








	global normalize_mac: function(a: string): string;
}

function has_valid_octets(octets: string_vec): bool
	{
	for ( i in octets )
		{
		local num = octets[i] as count;
		if ( 255 < num )
			return F;
		}
	return T;
	}

function extract_ip_addresses(input: string, check_wrapping: bool &default=F): string_vec
	{
	local parts = split_string_all(input, ip_addr_regex);
	local output: string_vec;

	for ( i in parts )
		{
		if ( i % 2 == 1 && is_valid_ip(parts[i]) )
			{
			if ( ! check_wrapping )
				{
				output += parts[i];
				}
			else if ( i > 0 && i < |parts| - 1 )
				{
				local p1 = parts[i-1];
				local p3 = parts[i+1];

				if ( ( |p1| == 0 && |p3| == 0 ) ||
				     ( p1[-1] == "\[" && p3[0] == "\]" ) ||
			             ( p1[-1] == "\(" && p3[0] == "\)" ) ||
			             ( p1[-1] == "\{" && p3[0] == "\}" ) ||
			             ( p1[-1] == " " && p3[0] == " " ) )
					output += parts[i];
				}
			}
		}
	return output;
	}

function addr_to_uri(a: addr): string
	{
	if ( is_v4_addr(a) )
		return fmt("%s", a);
	else
		return fmt("[%s]", a);
	}

function normalize_mac(a: string): string
	{
	local result = to_lower(gsub(a, /[^A-Fa-f0-9]/, ""));
	local octets: string_vec;

	if ( |result| == 12 )
		{
		octets = str_split_indices(result, vector(2, 4, 6, 8, 10));
		return fmt("%s:%s:%s:%s:%s:%s", octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]);
		}

	if ( |result| == 16 )
		{
		octets = str_split_indices(result, vector(2, 4, 6, 8, 10, 12, 14));
		return fmt("%s:%s:%s:%s:%s:%s:%s:%s", octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7]);
		}

	return "";
	}
