




@load base/protocols/dns/main

redef dns_skip_all_auth = F;
redef dns_skip_all_addl = F;

module DNS;

export {
	redef record Info += {

		auth:       set[string] &log &optional;

		addl:       set[string] &log &optional;
	};
}

hook DNS::do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string) &priority=5
	{
	if ( msg$opcode != 0 )

		return;

	if ( ! msg$QR )


		return;

	if ( ans$answer_type == DNS_AUTH )
		{
		if ( ! c$dns?$auth )
			c$dns$auth = set();
		add c$dns$auth[reply];
		}
	else if ( ans$answer_type == DNS_ADDL )
		{
		if ( ! c$dns?$addl )
			c$dns$addl = set();
		add c$dns$addl[reply];
		}
	}
