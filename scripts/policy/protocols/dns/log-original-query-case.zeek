


@load base/protocols/dns/main

module DNS;

export {
	redef record Info += {

		original_query: string &log &optional;
	};
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) &priority=5
	{
	if ( msg$opcode != 0 )

		return;

	c$dns$original_query = original_query;
	}
