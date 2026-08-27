


module TrimTraceFile;

export {

	const trim_interval = 10 mins &redef;






	global go: event(first_trim: bool);
	}

event TrimTraceFile::go(first_trim: bool)
	{
	if ( zeek_is_terminating() || trace_output_file == "" )
		return;

	if ( ! first_trim )
		{
		local info = rotate_file_by_name(trace_output_file);
		if ( info$old_name != "" )
			system(fmt("/bin/rm %s", safe_shell_quote(info$new_name)));
		}

	schedule trim_interval { TrimTraceFile::go(F) };
	}

event zeek_init()
	{
	if ( trim_interval > 0 secs )
		schedule trim_interval { TrimTraceFile::go(T) };
	}
