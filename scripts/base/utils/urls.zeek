





const url_regex = /^([a-zA-Z\-]{3,5}):\/\/(-\.)?([^[:blank:]\/?\.


type URI: record {

	scheme:       string &optional;


	netlocation:  string;

	portnum:      count &optional;

	path:         string;

	file_name:    string &optional;

	file_base:    string &optional;

	file_ext:     string &optional;


	params:       table[string] of string &optional;
};


function find_all_urls(s: string): string_set
	{
	return find_all(s, url_regex);
	}



function find_all_urls_without_scheme(s: string): string_set
	{
	local urls = find_all_urls(s);
	local return_urls: set[string] = set();
	for ( url in urls )
		{
		local no_scheme = sub(url, /^([a-zA-Z\-]{3,5})(:\/\/)/, "");
		add return_urls[no_scheme];
		}

	return return_urls;
	}

function decompose_uri(uri: string): URI
	{
	local parts: string_vec;
	local u = URI($netlocation="", $path="/");
	local s = uri;

	if ( /\?/ in s )
		{
		u$params = table();

		parts = split_string1(s, /\?/);
		s = parts[0];
		local query = parts[1];

		if ( /&/ in query )
			{
			local opv = split_string(query, /&/);

			for ( each in opv )
				{
				if ( /=/ in opv[each] )
					{
					parts = split_string1(opv[each], /=/);
					u$params[parts[0]] = parts[1];
					}
				}
			}
		else if ( /=/ in query )
			{
			parts = split_string1(query, /=/);
			u$params[parts[0]] = parts[1];
			}
		}

	if ( /:\/\// in s )
		{

		parts = split_string1(s, /:\/\//);
		u$scheme = parts[0];
		s = parts[1];
		}

	if ( /\// in s )
		{

		parts = split_string1(s, /\//);
		s = parts[0];
		u$path = fmt("/%s", parts[1]);

		if ( |u$path| > 1 && u$path[|u$path| - 1] != "/" )
			{
			local last_token = find_last(u$path, /\/.+/);
			local full_filename = split_string1(last_token, /\//)[1];

			if ( /\./ in full_filename )
				{
				u$file_name = full_filename;
				u$file_base = split_string1(full_filename, /\./)[0];
				u$file_ext  = split_string1(full_filename, /\./)[1];
				}
			else
				{
				u$file_name = full_filename;
				u$file_base = full_filename;
				}
			}
		}

	if ( /:[0-9]*$/ in s )
		{


		u$netlocation = gsub(s, /:[0-9]*$/, "");
		local portstr = s[|u$netlocation| + 1:];
		if ( portstr != "" )
			u$portnum = portstr as count;
		}
	else
		{
		u$netlocation = s;
		}

	return u;
	}
