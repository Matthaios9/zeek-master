



@load base/frameworks/control
@load base/frameworks/notice
@load base/frameworks/software

module Software;

export {
	redef enum Notice::Type += {

		Vulnerable_Version,
	};

	type VulnerableVersionRange: record {



		min:  Software::Version &optional;





		max:  Software::Version;
	};



	option vulnerable_versions_update_endpoint = "";



	option vulnerable_versions_update_interval = 1hr;




	const vulnerable_versions: table[string] of set[VulnerableVersionRange] = table() &redef;
}

global internal_vulnerable_versions: table[string] of set[VulnerableVersionRange] = table();

function decode_vulnerable_version_range(vuln_sw: string): VulnerableVersionRange
	{


	local vvr = Software::VulnerableVersionRange($max=Software::Version($major=0));

	if ( /max=/ !in vuln_sw )
		{
		Reporter::warning(fmt("The vulnerable software detection script encountered a version with no max value (which is required). %s", vuln_sw));
		return vvr;
		}

	local versions = split_string1(vuln_sw, /\x09/);

	for ( i in versions )
		{
		local field_and_ver = split_string1(versions[i], /=/);
		if ( |field_and_ver| != 2 )
			return vvr;

		local ver = Software::parse(field_and_ver[1])$version;
		if ( field_and_ver[0] == "min" )
			vvr$min = ver;
		else if ( field_and_ver[0] == "max" )
			vvr$max = ver;
		}

		return vvr;
	}

event grab_vulnerable_versions(i: count)
	{
	if ( vulnerable_versions_update_endpoint == "" )
		{

		schedule vulnerable_versions_update_interval { grab_vulnerable_versions(1) };
		return;
		}

	when [i] ( local result = lookup_hostname_txt(cat(i,".",vulnerable_versions_update_endpoint)) )
		{
		local parts = split_string1(result, /\x09/);
		if ( |parts| != 2 )
			{
			schedule vulnerable_versions_update_interval { grab_vulnerable_versions(1) };
			return;
			}

		local sw = parts[0];
		local vvr = decode_vulnerable_version_range(parts[1]);
		if ( sw !in internal_vulnerable_versions )
			internal_vulnerable_versions[sw] = set();
		add internal_vulnerable_versions[sw][vvr];

		event grab_vulnerable_versions(i+1);
		}
	timeout 5secs
		{

		schedule 1min { grab_vulnerable_versions(1) };
		}
	}

function update_vulnerable_sw()
	{
	internal_vulnerable_versions = table();


	for ( sw, vuln_range_set in vulnerable_versions )
		internal_vulnerable_versions[sw] = vuln_range_set;

	event grab_vulnerable_versions(1);
	}

event zeek_init() &priority=3
	{
	update_vulnerable_sw();
	}

event Control::configuration_update() &priority=3
	{
	update_vulnerable_sw();
	}

event log_software(rec: Info)
	{
	if ( rec$name !in internal_vulnerable_versions )
		return;

	for ( version_range in internal_vulnerable_versions[rec$name] )
		{
		if ( cmp_versions(rec$version, version_range$max) <= 0 &&
			 (!version_range?$min || cmp_versions(rec$version, version_range$min) >= 0) )
			{

			NOTICE(Notice::Info($note=Vulnerable_Version, $src=rec$host,
			                    $msg=fmt("%s is running %s which is vulnerable.", rec$host, software_fmt(rec)),
			                    $sub=software_fmt(rec)));
			}
		}
	}
