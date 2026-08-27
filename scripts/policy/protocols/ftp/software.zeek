







@load base/frameworks/software

module FTP;

export {
	redef enum Software::Type += {

		CLIENT,

		SERVER,
	};
}

event ftp_request(c: connection, command: string, arg: string) &priority=4
	{
	if ( command == "CLNT" )
		{
		Software::found(c$id, Software::Info($unparsed_version=arg, $host=c$id$orig_h, $software_type=CLIENT));
		}
	}
