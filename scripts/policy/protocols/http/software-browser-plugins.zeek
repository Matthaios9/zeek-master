


@load base/protocols/http
@load base/frameworks/software

module HTTP;

export {
	redef record Info += {

		omniture: bool &default=F;

		flash_version: string &optional;
	};

	redef enum Software::Type += {

		BROWSER_PLUGIN
	};
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( is_orig )
		{
		switch ( name )
			{
			case "X-FLASH-VERSION":


				c$http$flash_version = cat("Flash/", value);
				break;

			case "X-REQUESTED-WITH":


				if ( /Flash/ in value )
					c$http$flash_version = value;
				break;
			}
		}
	else
		{

		if ( name == "SERVER" && /^Omniture/ in value )
			c$http$omniture = T;
		}
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{

	if ( is_orig && c$http?$flash_version )
		{


		if( c$http?$user_agent )
			{
			if ( /AdobeAIR/ in c$http$user_agent )
				c$http$flash_version = cat("AdobeAIR-", c$http$flash_version);
			}

		Software::found(c$id, Software::Info($unparsed_version=c$http$flash_version, $host=c$id$orig_h, $software_type=BROWSER_PLUGIN));
		}
	}

event log_http(rec: Info)
	{


	if ( rec$omniture && rec?$uri )
		{

		local parts = split_string_n(rec$uri, /&p=([^&]{5,});&/, T, 1);
		if ( 1 in parts )
			{


			local sw = sub_bytes(parts[1], 4, |parts[1]|-5);
			local plugins = split_string(sw, /[[:blank:]]*;[[:blank:]]*/);

			for ( i in plugins )
				Software::found(rec$id, Software::Info($unparsed_version=plugins[i], $host=rec$id$orig_h, $software_type=BROWSER_PLUGIN));
			}
		}
	}
