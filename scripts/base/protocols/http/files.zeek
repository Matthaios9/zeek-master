@load ./main
@load ./entities
@load ./utils
@load base/utils/conn-ids
@load base/frameworks/files

module HTTP;

export {

	global get_file_handle: function(c: connection, is_orig: bool): string;


	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! c?$http )
		return "";

	if ( c$http$range_request && ! is_orig )
		{



		return cat(Analyzer::ANALYZER_HTTP, is_orig, c$id$orig_h, build_url(c$http));
		}
	else
		{
		local mime_depth = is_orig ? c$http$orig_mime_depth : c$http$resp_mime_depth;
		return cat(Analyzer::ANALYZER_HTTP, c$start_time, is_orig,
		           c$http$trans_depth, mime_depth, id_string(c$id));
		}
	}

function describe_file(f: fa_file): string
	{

	if ( f$source != "HTTP" )
		return "";

	for ( _, c in f$conns )
		{
		if ( c?$http )
			return build_url_http(c$http);
		}
	return "";
	}

event zeek_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_HTTP,
	                         Files::ProtoRegistration($get_file_handle = HTTP::get_file_handle,
	                                                  $describe        = HTTP::describe_file));
	}
