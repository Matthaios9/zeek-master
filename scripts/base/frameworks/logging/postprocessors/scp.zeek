














module Log;

export {











	global scp_postprocessor: function(info: Log::RotationInfo): bool;



	type SCPDestination: record {


		user: string;

		host: string;

		path: string;
	};






	global scp_destinations: table[Writer, string] of set[SCPDestination];



	const scp_rotation_date_format = "%Y-%m-%d-%H-%M-%S" &redef;
}

function scp_postprocessor(info: Log::RotationInfo): bool
	{
	if ( reading_traces() || [info$writer, info$path] !in scp_destinations )
		return T;

	local command = "";
	for ( d in scp_destinations[info$writer, info$path] )
		{
		local dst = fmt("%s/%s.%s.log", d$path, info$path,
                        strftime(Log::scp_rotation_date_format, info$open));
		command += fmt("scp %s %s@%s:%s;", info$fname, d$user, d$host, dst);
		}

	command += fmt("/bin/rm %s", safe_shell_quote(info$fname));
	system(command);
	return T;
	}
