

@load ./main
@load base/utils/addrs

module HTTP;

export {









	global extract_keys: function(data: string, kv_splitter: pattern): string_vec;







	global build_url: function(rec: Info): string;







	global build_url_http: function(rec: Info): string;


	global describe: function(rec: Info): string;
}


function extract_keys(data: string, kv_splitter: pattern): string_vec
	{
	local key_vec: vector of string = vector();

	local parts = split_string(data, kv_splitter);
	for ( part_index in parts )
		{
		local key_val = split_string1(parts[part_index], /=/);
		if ( 0 in key_val )
			key_vec += key_val[0];
		}
	return key_vec;
	}

function build_url(rec: Info): string
	{
	local uri  = rec?$uri ? rec$uri : "/<missed_request>";
	if ( strstr(uri, "://") != 0 )
		return uri;

	local host = rec?$host ? rec$host : addr_to_uri(rec$id$resp_h);
	local resp_p = rec$id$resp_p as count;
	if ( resp_p != 80 )
		host = fmt("%s:%d", host, resp_p);
	return fmt("%s%s", host, uri);
	}

function build_url_http(rec: Info): string
	{
	return fmt("http://%s", build_url(rec));
	}

function describe(rec: Info): string
	{
	return build_url_http(rec);
	}
