





@load base/frameworks/notice

module SSH;

export {
	redef enum Notice::Type += {



		Interesting_Hostname_Login,
	};


	option interesting_hostnames =
			/^d?ns[0-9]*\./ |
			/^smtp[0-9]*\./ |
			/^mail[0-9]*\./ |
			/^pop[0-9]*\./  |
			/^imap[0-9]*\./ |
			/^www[0-9]*\./  |
			/^ftp[0-9]*\./;
}

function check_ssh_hostname(id: conn_id, uid: string, host: addr)
	{
	when [id, uid, host] ( local hostname = lookup_addr(host) )
		{
		if ( interesting_hostnames in hostname )
			{
			NOTICE(Notice::Info($note=Interesting_Hostname_Login,
			                    $msg=fmt("Possible SSH login involving a %s %s with an interesting hostname.",
			                             Site::is_local_addr(host) ? "local" : "remote",
			                             host == id$orig_h ? "client" : "server"),
			                    $sub=hostname, $id=id, $uid=uid));
			}
		}
	}

event ssh_auth_successful(c: connection, auth_method_none: bool)
	{
	for ( host in set(c$id$orig_h, c$id$resp_h) )
		{
		check_ssh_hostname(c$id, c$uid, host);
		}
	}
