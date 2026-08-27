

@load base/protocols/ssh

module SSH;

export {
	redef record Info += {

		host_key:        string       &log &optional;
	};
}

event ssh_server_host_key(c: connection, hash: string) &priority=5
	{
	if ( ! c?$ssh )
		return;

	c$ssh$host_key = hash;
	}
