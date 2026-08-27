





@load base/utils/directions-and-hosts
@load base/utils/numbers
@load base/frameworks/cluster

module Software;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;




	type Type: enum {

		UNKNOWN,
	};


	type Version: record {

		major:  count  &optional;

		minor:  count  &optional;

		minor2: count  &optional;

		minor3: count  &optional;

		addl:   string &optional;
	} &log;


	type Info: record {

		ts:               time &log &optional;

		host:             addr &log;


		host_p:           port &log &optional;

		software_type:    Type &log &default=UNKNOWN;

		name:             string &log &optional;

		version:          Version &log &optional;



		unparsed_version: string &log &optional;








		force_log:        bool &default=F;
	};



	option asset_tracking = LOCAL_HOSTS;




	const parse_cache_interval = 65secs &redef;




	const found_cache_interval = 10mins &redef;





	const max_software_cache_size = 20 &redef;








	global found: function(id: conn_id, info: Info): bool;






	global cmp_versions: function(v1: Version, v2: Version): int;







	global alternate_names: table[string] of string = {
		["Flash Player"] = "Flash",
	} &default=function(a: string): string { return a; };




	type Set: record {


		versions: set[string];

		last: Info &optional;
	};





	type SoftwareSets: table[string] of Set;





	global tracked_software: table[addr] of SoftwareSets &create_expire=1day;

	type SoftwareSet: table[string] of Info &deprecated="Remove in v9.1. Use SoftwareSets instead.";
@pragma push ignore-deprecations
	global tracked: table[addr] of SoftwareSet &create_expire=1day &deprecated="Remove in v9.1. Unused. Use tracked_software instead.";
@pragma pop ignore-deprecations



	global log_software: event(rec: Info);



	global version_change: event(old: Info, new: Info);



	global register: event(info: Info);
}

type Description: record {
	name:             string;
	version:          Version;
	unparsed_version: string;
};


global parse_mozilla: function(unparsed_version: string): Description;



function parse(unparsed_version: string): Description
	{
	local software_name = "<parse error>";
	local v: Version;


	if ( /^(Mozilla|Opera)\/[0-9]+\./ in unparsed_version )
		{
		return parse_mozilla(unparsed_version);
		}
	else if ( /A\/[0-9\.]*\/Google\/Pixel/ in unparsed_version )
		{
		software_name = "Android (Google Pixel)";
		local parts = split_string_all(unparsed_version, /\//);
		if ( 2 in parts )
			{
			local vs = parts[2];

			if ( "." in vs )
				v = parse(vs)$version;
			else
				v = Version($major=extract_count(vs));

			return Description($version=v, $unparsed_version=unparsed_version, $name=software_name);
			}
		}
	else
		{


		local clean_unparsed_version = gsub(unparsed_version, /\\x/, "%");
		clean_unparsed_version = unescape_URI(clean_unparsed_version);
		local version_parts = split_string_n(clean_unparsed_version, /([\/\-_]|( [\(v]+))?[0-9\-\._, ]{2,}/, T, 1);
		if ( 0 in version_parts )
			{

			if ( /([\/\-_]|( [\(v]+))$/ in version_parts[0] )
				version_parts[0] = strip(sub(version_parts[0], /([\/\-_]|( [\(v]+))/, ""));

			if ( /^\(/ in version_parts[0] )
				software_name = strip(sub(version_parts[0], /\(/, ""));
			else
				software_name = strip(version_parts[0]);
			}
		if ( |version_parts| >= 2 )
			{


			local sv = strip(version_parts[1]);
			if ( /^[\/\-\._v\(]/ in sv )
				sv = strip(sub(sv, /^[\/\-\._v\(]/, ""));

			local version_numbers = split_string_n(sv, /[\-\._,\[\(\{ ]/, F, 3);
			if ( 4 in version_numbers && version_numbers[4] != "" )
				v$addl = strip(version_numbers[4]);
			else if ( 2 in version_parts && version_parts[2] != "" &&
			          version_parts[2] != ")" )
				{
				if ( /^[[:blank:]]*\([a-zA-Z0-9\-\._[:blank:]]*\)/ in version_parts[2] )
					{
					v$addl = split_string_n(version_parts[2], /[\(\)]/, F, 2)[1];
					}
				else
					{
					local vp = split_string_n(version_parts[2], /[\-\._,;\[\]\(\)\{\} ]/, F, 3);
					if ( |vp| >= 1 && vp[0] != "" )
						{
						v$addl = strip(vp[0]);
						}
					else if ( |vp| >= 2 && vp[1] != "" )
						{
						v$addl = strip(vp[1]);
						}
					else if ( |vp| >= 3 && vp[2] != "" )
						{
						v$addl = strip(vp[2]);
						}
					else
						{
						v$addl = strip(version_parts[2]);
						}

					}
				}

			if ( 3 in version_numbers && version_numbers[3] != "" )
				v$minor3 = extract_count(version_numbers[3]);
			if ( 2 in version_numbers && version_numbers[2] != "" )
				v$minor2 = extract_count(version_numbers[2]);
			if ( 1 in version_numbers && version_numbers[1] != "" )
				v$minor = extract_count(version_numbers[1]);
			if ( 0 in version_numbers && version_numbers[0] != "" )
				v$major = extract_count(version_numbers[0]);
			}
		}

	return Description($version=v, $unparsed_version=unparsed_version, $name=alternate_names[software_name]);
	}


global parse_cache: table[string] of Description;

global found_cache: set[Info];


function parse_with_cache(unparsed_version: string): Description
	{
	if (unparsed_version in parse_cache)
		return parse_cache[unparsed_version];

	local res = parse(unparsed_version);
	parse_cache[unparsed_version] = res;
	return res;
	}

function parse_mozilla(unparsed_version: string): Description
	{
	local software_name = "<unknown browser>";
	local v: Version;
	local parts: string_vec;

	if ( /Opera [0-9\.]*$/ in unparsed_version )
		{
		software_name = "Opera";
		parts = split_string_all(unparsed_version, /Opera [0-9\.]*$/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}
	else if ( / MSIE |Trident\// in unparsed_version )
		{
		software_name = "MSIE";
		if ( /Trident\/4\.0/ in unparsed_version )
			v = Version($major=8,$minor=0);
		else if ( /Trident\/5\.0/ in unparsed_version )
			v = Version($major=9,$minor=0);
		else if ( /Trident\/6\.0/ in unparsed_version )
			v = Version($major=10,$minor=0);
		else if ( /Trident\/7\.0/ in unparsed_version )
			v = Version($major=11,$minor=0);
		else
			{
			parts = split_string_all(unparsed_version, /MSIE [0-9]{1,2}\.*[0-9]*b?[0-9]*/);
			if ( 1 in parts )
				v = parse(parts[1])$version;
			}
		}
	else if ( /Edge\// in unparsed_version )
		{
		software_name="Edge";
		parts = split_string_all(unparsed_version, /Edge\/[0-9\.]*/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}
	else if ( /Version\/.*Safari\// in unparsed_version )
		{
		software_name = "Safari";
		parts = split_string_all(unparsed_version, /Version\/[0-9\.]*/);
		if ( 1 in parts )
			{
			v = parse(parts[1])$version;
			if ( / Mobile\/?.* Safari/ in unparsed_version )
				v$addl = "Mobile";
			}
		}
	else if ( /(Firefox|Netscape|Thunderbird)\/[0-9\.]*/ in unparsed_version )
		{
		parts = split_string_all(unparsed_version, /(Firefox|Netscape|Thunderbird)\/[0-9\.]*/);
		if ( 1 in parts )
			{
			local tmp_s = parse(parts[1]);
			software_name = tmp_s$name;
			v = tmp_s$version;
			}
		}
	else if ( /Chrome\/.*Safari\// in unparsed_version )
		{
		software_name = "Chrome";
		parts = split_string_all(unparsed_version, /Chrome\/[0-9\.]*/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}
	else if ( /^Opera\// in unparsed_version )
		{
		if ( /Opera M(ini|obi)\// in unparsed_version )
			{
			parts = split_string_all(unparsed_version, /Opera M(ini|obi)/);
			if ( 1 in parts )
				software_name = parts[1];
			parts = split_string_all(unparsed_version, /Version\/[0-9\.]*/);
			if ( 1 in parts )
				v = parse(parts[1])$version;
			else
				{
				parts = split_string_all(unparsed_version, /Opera Mini\/[0-9\.]*/);
				if ( 1 in parts )
					v = parse(parts[1])$version;
				}
			}
		else
			{
			software_name = "Opera";
			parts = split_string_all(unparsed_version, /Version\/[0-9\.]*/);
			if ( 1 in parts )
				v = parse(parts[1])$version;
			}
		}
	else if ( /Flash%20Player/ in unparsed_version )
		{
		software_name = "Flash";
		parts = split_string_all(unparsed_version, /[\/ ]/);
		if ( 2 in parts )
			v = parse(parts[2])$version;
		}

	else if ( /AdobeAIR\/[0-9\.]*/ in unparsed_version )
		{
		software_name = "AdobeAIR";
		parts = split_string_all(unparsed_version, /AdobeAIR\/[0-9\.]*/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}
	else if ( /AppleWebKit\/[0-9\.]*/ in unparsed_version )
		{
		software_name = "Unspecified WebKit";
		parts = split_string_all(unparsed_version, /AppleWebKit\/[0-9\.]*/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}
	else if ( / Java\/[0-9]\./ in unparsed_version )
		{
		software_name = "Java";
		parts = split_string_all(unparsed_version, /Java\/[0-9\._]*/);
		if ( 1 in parts )
			v = parse(parts[1])$version;
		}

	return Description($version=v, $unparsed_version=unparsed_version, $name=software_name);
	}


function cmp_versions(v1: Version, v2: Version): int
	{
	if ( v1?$major && v2?$major )
		{
		if ( v1$major < v2$major )
			return -1;
		if ( v1$major > v2$major )
			return 1;
		}
	else
		{
		if ( !v1?$major && !v2?$major )
			{ }
		else
			return v1?$major ? 1 : -1;
		}

	if ( v1?$minor && v2?$minor )
		{
		if ( v1$minor < v2$minor )
			return -1;
		if ( v1$minor > v2$minor )
			return 1;
		}
	else
		{
		if ( !v1?$minor && !v2?$minor )
			{ }
		else
			return v1?$minor ? 1 : -1;
		}

	if ( v1?$minor2 && v2?$minor2 )
		{
		if ( v1$minor2 < v2$minor2 )
			return -1;
		if ( v1$minor2 > v2$minor2 )
			return 1;
		}
	else
		{
		if ( !v1?$minor2 && !v2?$minor2 )
			{ }
		else
			return v1?$minor2 ? 1 : -1;
		}

	if ( v1?$minor3 && v2?$minor3 )
		{
		if ( v1$minor3 < v2$minor3 )
			return -1;
		if ( v1$minor3 > v2$minor3 )
			return 1;
		}
	else
		{
		if ( !v1?$minor3 && !v2?$minor3 )
			{ }
		else
			return v1?$minor3 ? 1 : -1;
		}

	if ( v1?$addl && v2?$addl )
		{
		return strcmp(v1$addl, v2$addl);
		}
	else
		{
		if ( !v1?$addl && !v2?$addl )
			return 0;
		else
			return v1?$addl ? 1 : -1;
		}


	return 0;
	}



function software_fmt_version(v: Version): string &is_used
	{
	return fmt("%s%s%s%s%s",
	           v?$major ? fmt("%d", v$major) : "0",
	           v?$minor ? fmt(".%d", v$minor) : "",
	           v?$minor2 ? fmt(".%d", v$minor2) : "",
	           v?$minor3 ? fmt(".%d", v$minor3) : "",
	           v?$addl ? fmt("-%s", v$addl) : "");
	}




function software_fmt_unparsed_version(i: Info): string
	{
	if ( i?$unparsed_version )
		return i$unparsed_version;
	if ( i?$version )
		return software_fmt_version(i$version);




	Reporter::error("Software::Info record has neither version nor unparsed_version");
	return "<unknown>";
	}


function software_fmt(i: Info): string &is_used
	{
	return fmt("%s %s", i$name, software_fmt_version(i$version));
	}

function software_in_sets(info: Info, ss: SoftwareSets): bool
	{
	if ( info$name in ss && software_fmt_unparsed_version(info) in ss[info$name]$versions )
		return T;

	return F;
	}




event Software::new(info: Info)
	{
	if ( ! info?$version )
		{
		local sw = parse_with_cache(info$unparsed_version);
		info$unparsed_version = sw$unparsed_version;
		info$name = sw$name;
		info$version = sw$version;
		}

	event Software::register(info);
	}

event Software::register(info: Info)
	{
	local ss: SoftwareSets;

	if ( info$host in tracked_software )
		ss = tracked_software[info$host];
	else
		ss = tracked_software[info$host] = SoftwareSets();



	if ( software_in_sets(info, ss) )
		{
		if ( ! info$force_log )
			return;
		}
	else
		{
		if ( info$name !in ss )
			ss[info$name] = Set();
		else
			event Software::version_change(ss[info$name]$last, info);

		add ss[info$name]$versions[software_fmt_unparsed_version(info)];
		ss[info$name]$last = info;




		if ( max_software_cache_size > 0 && |ss[info$name]$versions| > max_software_cache_size )
			ss[info$name]$versions = {software_fmt_unparsed_version(info)};
		}

	Log::write(Software::LOG, info);
	}

function found(id: conn_id, info: Info): bool
	{
	if ( ! info$force_log && ! addr_matches_host(info$host, asset_tracking) )
		return F;


	if ( found_cache_interval > 0secs )
		{
		if ( info in found_cache )
			return T;
		add found_cache[info];
		}

	if ( ! info?$ts )
		info$ts = network_time();

	if ( info?$version )
		{
		if ( ! info?$name )
			{
			Reporter::error("Required field name not present in Software::found");
			return F;
			}
		}
	else if ( ! info?$unparsed_version )
		{
		Reporter::error("No unparsed version string present in Info record with version in Software::found");
		return F;
		}

	@if ( Cluster::is_enabled() )
		Cluster::publish_hrw(Cluster::proxy_pool, info$host, Software::new, info);
	@else
		event Software::new(info);
	@endif

	return T;
	}

event zeek_init() &priority=5
	{
	parse_cache = table() &read_expire=parse_cache_interval;

	if ( found_cache_interval > 0secs )
		found_cache = set() &create_expire=found_cache_interval;

	Log::create_stream(Software::LOG, Log::Stream($columns=Info, $ev=log_software, $path="software", $policy=log_policy));
	}
