



module Version;

export {

	type VersionDescription: record {




		version_number: count;

		major: count;

		minor: count;

		patch: count;






		commit: count;



		beta: bool;

		debug: bool;

		localversion: string;

		version_string: string;
	};






	global parse: function(version_string: string): VersionDescription;







	global at_least: function(version_string: string): bool;
}

function parse(version_string: string): VersionDescription
	{
	if ( /[0-9]+\.[0-9]+(\.[0-9]+)?(-(beta|rc|dev)[0-9]*)?(\.[0-9]+)?(-[a-zA-Z0-9_\.]+)?(-debug)?/ != version_string )
		{
		Reporter::error(fmt("Version string %s cannot be parsed", version_string));
		return VersionDescription($version_number=0, $major=0, $minor=0, $patch=0, $commit=0, $beta=F, $debug=F, $localversion="", $version_string=version_string);
		}

	local beta = /-(beta|rc)/ in version_string;
	local debug = /-debug/ in version_string;
	local patchlevel = 0;
	local commit = 0;
	local vs = version_string;
	local localversion = "";

	local parts = split_string1(vs, /\./);
	local major = parts[0] as count;

	vs = lstrip(vs, "1234567890");
	vs = lstrip(vs, ".");

	parts = split_string1(vs, /\.|-/);
	local minor = parts[0] as count;

	vs = lstrip(vs, "1234567890");

	if ( |vs| > 0 )
		{

		if ( vs[0] == "." )
			{
			vs = lstrip(vs, ".");
			parts = split_string1(vs, /\.|-/);
			patchlevel = parts[0] as count;
			vs = lstrip(vs, "1234567890");
			}

		vs = gsub(vs, /-debug$/, "");
		vs = gsub(vs, /-(beta|rc|dev)[0-9]*/, "");
		localversion = find_last(vs, /-[a-zA-Z0-9_\.]+$/);
                if ( localversion != "" )
			{

			localversion = lstrip(localversion, "-");

			vs = gsub(vs, /-[a-zA-Z0-9_\.]+$/, "");
			}


		vs = lstrip(vs, ".");

		if ( |vs| > 0 )
			commit = vs as count;
		}

	local version_number = major * 10000 + minor * 100 + patchlevel;

	return VersionDescription($version_number=version_number, $major=major,
	                          $minor=minor, $patch=patchlevel, $commit=commit,
	                          $beta=beta, $debug=debug,
				  $localversion=localversion,
	                          $version_string=version_string);
	}

export {


	const info = Version::parse(zeek_version());






	const number = info$version_number;
}

function at_least(version_string: string): bool
	{
	return Version::number >= Version::parse(version_string)$version_number;
	}
