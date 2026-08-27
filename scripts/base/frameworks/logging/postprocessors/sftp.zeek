














module Log;

export {











	global sftp_postprocessor: function(info: Log::RotationInfo): bool;



	type SFTPDestination: record {


		user: string;

		host: string;

		host_port: count &default=22;

		path: string;
	};






	global sftp_destinations: table[Writer, string] of set[SFTPDestination];



	const sftp_rotation_date_format = "%Y-%m-%d-%H-%M-%S" &redef;
}

function sftp_postprocessor(info: Log::RotationInfo): bool
	{
	if ( reading_traces() || [info$writer, info$path] !in sftp_destinations )
		return T;

	local command = "";
	for ( d in sftp_destinations[info$writer, info$path] )
		{
		local dst = fmt("%s/%s.%s.log", d$path, info$path,
		                strftime(Log::sftp_rotation_date_format, info$open));
		command += fmt("echo put %s %s | sftp -P %d -b - %s@%s;", info$fname, dst,
		               d$host_port, d$user, d$host);
		}

	command += fmt("/bin/rm %s", safe_shell_quote(info$fname));
	system(command);
	return T;
	}
