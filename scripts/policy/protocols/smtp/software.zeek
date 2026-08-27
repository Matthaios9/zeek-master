








@load base/frameworks/software/main
@load base/protocols/smtp/main

module SMTP;

export {
	redef enum Software::Type += {
		MAIL_CLIENT,
		MAIL_SERVER,
		WEBMAIL_SERVER
	};

	redef record Info += {


		is_webmail: bool &log &default=F;
	};









	option detect_clients_in_messages_from = LOCAL_HOSTS;



	option webmail_user_agents =
	                     /^iPlanet Messenger/
	                   | /^Sun Java\(tm\) System Messenger Express/
	                   | /\(IMP\)/
	                   | /^SquirrelMail/
	                   | /^NeoMail/
	                   | /ZimbraWebClient/;
}

event mime_one_header(c: connection, h: mime_header_rec) &priority=4
	{
	if ( ! c?$smtp || ! c$smtp?$user_agent ) return;
	if ( h$name == "USER-AGENT" && webmail_user_agents in c$smtp$user_agent )
		c$smtp$is_webmail = T;
	}

event log_smtp(rec: Info)
	{



	if ( rec?$user_agent )
		{
		local s_type = MAIL_CLIENT;
		local client_ip = rec$path[|rec$path|-1];
		if ( rec$is_webmail )
			{
			s_type = WEBMAIL_SERVER;



			if ( rec?$first_received && /via HTTP/ in rec$first_received )
				client_ip = rec$path[|rec$path|-2];
			}

		if ( addr_matches_host(rec$id$orig_h,
		                       detect_clients_in_messages_from) )
			{
			Software::found(rec$id, Software::Info($unparsed_version=rec$user_agent, $host=client_ip, $software_type=s_type));
			}
		}
	}
