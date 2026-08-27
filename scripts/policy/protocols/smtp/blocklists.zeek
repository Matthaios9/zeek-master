

@load base/protocols/smtp
@load base/frameworks/notice

module SMTP;

export {
	redef enum Notice::Type += {

		Blocklist_Error_Message,



		Blocklist_Blocked_Host,
	};



	option blocklist_error_messages =
		  /spamhaus\.org\//
		| /sophos\.com\/security\//
		| /spamcop\.net\/bl/
		| /cbl\.abuseat\.org\//
		| /sorbs\.net\//
		| /bsn\.borderware\.com\//
		| /mail-abuse\.com\//
		| /b\.barracudacentral\.com\//
		| /psbl\.surriel\.com\//
		| /antispam\.imp\.ch\//
		| /dyndns\.com\/.*spam/
		| /rbl\.knology\.net\//
		| /intercept\.datapacket\.net\//
		| /uceprotect\.net\//
		| /hostkarma\.junkemailfilter\.com\//;

}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=3
	{
	if ( code >= 400 && code != 421 )
		{

		if ( blocklist_error_messages in msg )
			{
			local note = Blocklist_Error_Message;
			local message = fmt("%s received an error message mentioning an SMTP block list", c$id$orig_h);


			local ips = extract_ip_addresses(msg);
			local text_ip = "";
			if ( |ips| > 0 && ips[0] as addr == c$id$orig_h )
				{
				note = Blocklist_Blocked_Host;
				message = fmt("%s is on an SMTP block list", c$id$orig_h);
				}

			NOTICE(Notice::Info($note=note, $conn=c, $msg=message, $sub=msg,
			                    $identifier=cat(c$id$orig_h)));
			}
		}
	}
