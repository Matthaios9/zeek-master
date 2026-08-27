

@load base/frameworks/software

module MySQL;

export {
	redef enum Software::Type += {

		SERVER,
	};
}

event mysql_server_version(c: connection, ver: string)
	{
	if ( ver == "" )
		return;

	Software::found(c$id, Software::Info($unparsed_version=ver, $host=c$id$resp_h, $software_type=SERVER));
	}
