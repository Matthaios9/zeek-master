


@load base/frameworks/software

module SSH;

export {
	redef enum Software::Type += {

		SERVER,

		CLIENT,
	};
}

event ssh_client_version(c: connection, version: string) &priority=4
	{

	local cleaned_version = sub(version, /^SSH[0-9\.\-]+/, "");
	Software::found(c$id, Software::Info($unparsed_version=cleaned_version, $host=c$id$orig_h, $software_type=CLIENT));
	}

event ssh_server_version(c: connection, version: string) &priority=4
	{

	local cleaned_version = sub(version, /SSH[0-9\.\-]{2,}/, "");
	Software::found(c$id, Software::Info($unparsed_version=cleaned_version, $host=c$id$resp_h, $host_p=c$id$resp_p, $software_type=SERVER));
	}
