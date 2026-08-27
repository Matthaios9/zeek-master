

@load ./patterns

module Site;

export {










	option private_address_space: set[subnet] = {

		0.0.0.0/8,

		[2002::]/24,


		10.0.0.0/8,

		[2002:a00::]/24,


		100.64.0.0/10,

		[2002:6440::]/26,


		127.0.0.0/8,

		[2002:7f00::]/24,


		169.254.0.0/16,

		[2002:a9fe::]/32,


		172.16.0.0/12,

		[2002:ac10::]/28,


		192.0.0.0/24,

		[2002:c000::]/40,


		192.0.2.0/24,

		[2002:c000:200::]/40,


		192.168.0.0/16,

		[2002:c0a8::]/32,


		198.18.0.0/15,

		[2002:c612::]/31,


		198.51.100.0/24,

		[2002:c633:6400::]/40,


		203.0.113.0/24,

		[2002:cb00:7100::]/40,


		224.0.0.0/24,

		[2002:e000::]/40,


		239.0.0.0/8,

		[2002:ef00::]/24,


		240.0.0.0/4,

		[2002:f000::]/20,


		255.255.255.255/32,

		[2002:ffff:ffff::]/48,



		[::]/128,

		[::1]/128,

		[64:ff9b:1::]/48,

		[100::]/64,

		[2001::]/23,

		[2001:2::]/48,

		[2001:db8::]/32,

		[fc00::]/7,

		[fe80::]/10,

		[fec0::]/10,
	};



	option local_nets: set[subnet] = {};





	const private_address_space_is_local = T &redef;






	global local_nets_table: table[subnet] of subnet = {};


	option neighbor_nets: set[subnet] = {};





	option local_admins: table[subnet] of set[string] = {};


	option local_zones: set[string] = {};


	option neighbor_zones: set[string] = {};




	global is_local_addr: function(a: addr): bool;




	global is_neighbor_addr: function(a: addr): bool;




	global is_private_addr: function(a: addr): bool;




	global is_local_name: function(name: string): bool;




	global is_neighbor_name: function(name: string): bool;





	global get_emails: function(a: addr): string;
}


global local_dns_suffix_regex: pattern = /MATCH_NOTHING/;
global local_dns_neighbor_suffix_regex: pattern = /MATCH_NOTHING/;



global local_nets_needs_private_address_space = T;

function is_local_addr(a: addr): bool
	{
	return a in local_nets;
	}

function is_neighbor_addr(a: addr): bool
	{
	return a in neighbor_nets;
	}

function is_private_addr(a: addr): bool
	{
	return a in private_address_space;
	}

function is_local_name(name: string): bool
	{
	return local_dns_suffix_regex in name;
	}

function is_neighbor_name(name: string): bool
	{
	return local_dns_neighbor_suffix_regex in name;
	}


const one_to_32: vector of count = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};


function find_all_emails(ip: addr): set[string]
	{
	if ( ip !in local_admins ) return set();

	local output_values: set[string] = set();
	local tmp_subnet: subnet;
	local i: count;
	local emails: string;
	for ( i in one_to_32 )
		{
		tmp_subnet = mask_addr(ip, one_to_32[i]);
		if ( tmp_subnet in local_admins )
			for ( email in local_admins[tmp_subnet] )
				{
				if ( email != "" )
					add output_values[email];
			}
		}
	return output_values;
	}

function fmt_email_string(emails: set[string]): string
	{
	local output="";
	for( email in emails )
		{
		if ( output == "" )
			output = email;
		else
			output = fmt("%s, %s", output, email);
		}
	return output;
	}

function get_emails(a: addr): string
	{
	return fmt_email_string(find_all_emails(a));
	}

function update_local_nets_table(id: string, new_value: set[subnet]): set[subnet]
	{
	local result = new_value;





	if ( private_address_space_is_local )
		{
		if ( local_nets_needs_private_address_space )
			result = new_value | Site::private_address_space;
		local_nets_needs_private_address_space = T;
		}


	local_nets_table = {};

	for ( cidr in result )
		local_nets_table[cidr] = cidr;

	return result;
	}

function update_local_zones_regex(id: string, new_value: set[string]): set[string]
	{

	local_dns_suffix_regex = set_to_regex(new_value, "(^\\.?|\\.)(~~)$");
	return new_value;
	}

function update_neighbor_zones_regex(id: string, new_value: set[string]): set[string]
	{
	local_dns_neighbor_suffix_regex = set_to_regex(new_value, "(^\\.?|\\.)(~~)$");
	return new_value;
	}

function update_private_address_space(id: string, new_value: set[subnet]): set[subnet]
	{




	local new_privates = new_value - private_address_space;
	local old_privates = private_address_space - new_value;




	local new_local_nets = (local_nets | private_address_space) - old_privates;
	new_local_nets += new_privates;








	local_nets_needs_private_address_space = F;




	Option::set("Site::local_nets", new_local_nets, "<skip-config-log>");

	return new_value;
	}

event zeek_init() &priority=10
	{


	Option::set_change_handler("Site::local_nets", update_local_nets_table, -5);
	Option::set_change_handler("Site::local_zones", update_local_zones_regex, -5);
	Option::set_change_handler("Site::neighbor_zones", update_neighbor_zones_regex, -5);




	if ( private_address_space_is_local )
		{
		Option::set_change_handler("Site::private_address_space", update_private_address_space, -5);
		update_private_address_space("Site::private_address_space", Site::private_address_space);
		}



	update_local_nets_table("Site::local_nets", Site::local_nets);
	update_local_zones_regex("Site::local_zones", Site::local_zones);
	update_neighbor_zones_regex("Site::neighbor_zones", Site::neighbor_zones);
	}
