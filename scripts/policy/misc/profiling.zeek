

module Profiling;

function log_suffix(): string
	{
	local rval = getenv("ZEEK_LOG_SUFFIX");

	if ( rval == "" )
		return "log";

	return rval;
	}


redef profiling_file = open(fmt("prof.%s", Profiling::log_suffix()));


redef profiling_interval = 15 secs;



redef expensive_profiling_multiple = 20;

event zeek_init()
	{
	set_buf(profiling_file, F);
	}
