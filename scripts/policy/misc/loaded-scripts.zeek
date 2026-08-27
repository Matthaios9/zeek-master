
@load base/utils/paths

module LoadedScripts;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {



		name: string &log;
	};
}



function get_indent(level: count): string
	{
	local out = "";
	while ( level > 0 )
		{
		--level;
		out = out + "  ";
		}
	return out;
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LoadedScripts::LOG, Log::Stream($columns=Info, $path="loaded_scripts", $policy=log_policy));
	}

event zeek_script_loaded(path: string, level: count)
	{
	Log::write(LOG, Info($name=cat(get_indent(level), compress_path(path))));
	}
