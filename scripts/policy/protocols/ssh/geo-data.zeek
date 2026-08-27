

@load base/frameworks/notice
@load base/protocols/ssh

module SSH;

export {
	redef enum Notice::Type += {



		Watched_Country_Login,
	};

	redef record Info += {


		remote_location: geo_location &log &optional;
	};



	option watched_countries: set[string] = {"RO"};
}

function get_location(c: connection): geo_location
	{
	local lookup_ip = (c$ssh$direction == OUTBOUND) ? c$id$resp_h : c$id$orig_h;
	return lookup_location(lookup_ip);
	}

event ssh_auth_successful(c: connection, auth_method_none: bool) &priority=3
	{
	if ( ! c$ssh?$direction )
		return;

	if ( ! c$ssh?$remote_location )
		return;

	if ( c$ssh$remote_location?$country_code && c$ssh$remote_location$country_code in watched_countries )
		{
		NOTICE(Notice::Info($note=Watched_Country_Login,
		                    $conn=c,
		                    $msg=fmt("SSH login %s watched country: %s",
		                             (c$ssh$direction == OUTBOUND) ? "to" : "from",
		                             c$ssh$remote_location$country_code)));
		}
	}

event ssh_auth_attempted(c: connection, authenticated: bool) &priority=3
	{
	if ( ! c$ssh?$direction )
		return;


	c$ssh$remote_location = get_location(c);
	}
