



@load base/protocols/http/main

module HTTP;

export {
	redef record Info += {


		client_header_names:  vector of string &log &optional;



		server_header_names:  vector of string &log &optional;
	};


	option log_client_header_names = T;


	option log_server_header_names = F;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( ! c?$http )
		return;

	if ( is_orig )
		{
		if ( log_client_header_names )
			{
			if ( ! c$http?$client_header_names )
				c$http$client_header_names = vector();
			c$http$client_header_names += name;
			}
		}
	else
		{
		if ( log_server_header_names )
			{
			if ( ! c$http?$server_header_names )
				c$http$server_header_names = vector();
			c$http$server_header_names += name;
			}
		}
	}
