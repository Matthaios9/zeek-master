


@load base/utils/queue
@load ./consts
@load base/protocols/conn/removal-hooks

module DNS;

export {

	redef enum Log::ID += { LOG };


	const ports = { 53/udp, 53/tcp, 137/udp, 5353/udp, 5355/udp } &redef;


	global log_policy: Log::PolicyHook;


	type Info: record {


		ts:            time               &log;


		uid:           string             &log;

		id:            conn_id            &log;

		proto:         transport_proto    &log;



		trans_id:      count              &log &optional;



		rtt:           interval           &log &optional;

		query:         string             &log &optional;

		qclass:        count              &log &optional;

		qclass_name:   string             &log &optional;

		qtype:         count              &log &optional;

		qtype_name:    string             &log &optional;

		rcode:         count              &log &optional;

		rcode_name:    string             &log &optional;



		AA:            bool               &log &default=F;

		TC:            bool               &log &default=F;


		RD:            bool               &log &default=F;


		RA:            bool               &log &default=F;



		Z:             count              &log &default=0;

		answers:       vector of string   &log &optional;


		TTLs:          vector of interval &log &optional;

		rejected:      bool               &log &default=F;

		opcode:        count              &log &optional;

		opcode_name:   string             &log &optional;



		total_answers: count           &optional;


		total_replies: count           &optional;


		saw_query: bool                &default=F;

		saw_reply: bool                &default=F;
	};



	global log_dns: event(rec: Info);













	global do_reply: hook(c: connection, msg: dns_msg, ans: dns_answer, reply: string);










	global set_session: hook(c: connection, msg: dns_msg, is_query: bool);



	type PendingMessages: table[count] of Queue::Queue;





	option multicast_subnets: set[subnet] = { 224.0.0.0/4, [ff00::]/8 };






	option max_pending_msgs = 50;




	option max_pending_query_ids = 50;



	type State: record {





		pending_query: Info &optional;



		pending_queries: PendingMessages &optional;



		pending_replies: PendingMessages &optional;
	};


	global finalize_dns: Conn::RemovalHook;
}


redef record connection += {
	dns:       Info  &optional;
	dns_state: State &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(DNS::LOG, Log::Stream($columns=Info, $ev=log_dns, $path="dns", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_DNS, ports);
	}

function new_session(c: connection, trans_id: count): Info
	{
	local info: Info;
	info$ts       = network_time();
	info$id       = c$id;
	info$uid      = c$uid;
	info$proto    = get_port_transport_proto(c$id$resp_p);
	info$trans_id = trans_id;
	return info;
	}

function log_unmatched_msgs_queue(q: Queue::Queue)
	{
	local infos: vector of Info;
	Queue::get_vector(q, infos);

	for ( i in infos )
		{
		Log::write(DNS::LOG, infos[i]);
		}
	}

function log_unmatched_msgs(msgs: PendingMessages)
	{
	for ( _, q in msgs )
		{
		log_unmatched_msgs_queue(q);
		}

	clear_table(msgs);
	}

function enqueue_new_msg(msgs: PendingMessages, id: count, msg: Info)
	{
	if ( id !in msgs )
		{
		if ( |msgs| > max_pending_query_ids )
			{

			log_unmatched_msgs(msgs);
			}

		msgs[id] = Queue::init();
		}
	else
		{
		if ( Queue::len(msgs[id]) > max_pending_msgs )
			{
			log_unmatched_msgs_queue(msgs[id]);

			msgs[id] = Queue::init();
			}
		}

	Queue::put(msgs[id], msg);
	}

function pop_msg(msgs: PendingMessages, id: count): Info
	{
	local rval: Info = Queue::get(msgs[id]);

	if ( Queue::len(msgs[id]) == 0 )
		delete msgs[id];

	return rval;
	}

hook set_session(c: connection, msg: dns_msg, is_query: bool) &priority=5
	{
	if ( ! c?$dns_state )
		{
		local state: State;
		c$dns_state = state;
		Conn::register_removal_hook(c, finalize_dns);
		}




	if ( c$id$resp_h in multicast_subnets )
		{
		c$dns = new_session(c, msg$id);



		c$dns$saw_query = T;
		c$dns$saw_reply = T;
		}
	else if ( is_query )
		{
		if ( c$dns_state?$pending_replies && msg$id in c$dns_state$pending_replies &&
		     Queue::len(c$dns_state$pending_replies[msg$id]) > 0 )
			{

			c$dns = pop_msg(c$dns_state$pending_replies, msg$id);
			}
		else
			{


			c$dns = new_session(c, msg$id);

			if( ! c$dns_state?$pending_query )
				c$dns_state$pending_query = c$dns;
			else
				{
				if( !c$dns_state?$pending_queries )
					c$dns_state$pending_queries = table();

				enqueue_new_msg(c$dns_state$pending_queries, msg$id, c$dns);
				}
			}
		}
	else
		{
		if ( c$dns_state?$pending_query && c$dns_state$pending_query$trans_id == msg$id )
			{
			c$dns = c$dns_state$pending_query;
			delete c$dns_state$pending_query;

			if ( c$dns_state?$pending_queries )
				{








				if ( msg$id in c$dns_state$pending_queries &&
				     Queue::len(c$dns_state$pending_queries[msg$id]) > 0 )


					c$dns_state$pending_query = pop_msg(c$dns_state$pending_queries, msg$id);
				else
					{

					local tid: count &is_assigned;
					local found_one = F;

					for ( trans_id, q in c$dns_state$pending_queries )
						if ( Queue::len(q) > 0 )
							{
							tid = trans_id;
							found_one = T;
							break;
							}

					if ( found_one )
						c$dns_state$pending_query = pop_msg(c$dns_state$pending_queries, tid);
					}
				}
			}
		else if ( c$dns_state?$pending_queries && msg$id in c$dns_state$pending_queries &&
		     Queue::len(c$dns_state$pending_queries[msg$id]) > 0 )
			{

			c$dns = pop_msg(c$dns_state$pending_queries, msg$id);
			}
		else
			{


			c$dns = new_session(c, msg$id);

			if( ! c$dns_state?$pending_replies )
				c$dns_state$pending_replies = table();

			enqueue_new_msg(c$dns_state$pending_replies, msg$id, c$dns);
			}
		}

	if ( ! is_query )
		{
		c$dns$rcode = msg$rcode;
		c$dns$rcode_name = base_errors[msg$rcode];

		if ( ! c$dns?$total_answers )
			c$dns$total_answers = msg$num_answers;

		if ( ! c$dns?$total_replies )
			c$dns$total_replies = msg$num_answers + msg$num_addl + msg$num_auth;

		if ( msg$rcode != 0 && msg$num_queries == 0 )
			c$dns$rejected = T;
		}

	c$dns$opcode = msg$opcode;
	if ( msg$is_netbios )
		c$dns$opcode_name = netbios_opcodes[msg$opcode];
	else
		c$dns$opcode_name = opcodes[msg$opcode];
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) &priority=5
	{
	if ( msg$opcode != DNS_OP_QUERY && msg$opcode != DNS_OP_DYNAMIC_UPDATE && msg$opcode != DNS_OP_NOTIFY )

		return;

	hook set_session(c, msg, ! msg$QR);
	}

hook DNS::do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string) &priority=5
	{
	if ( msg$opcode != DNS_OP_QUERY && msg$opcode != DNS_OP_DYNAMIC_UPDATE && msg$opcode != DNS_OP_NOTIFY )

		return;

	if ( ! msg$QR )


		return;

	if ( ans$answer_type != DNS_ANS &&
	     ans$answer_type != DNS_PREREQUISITE &&
	     ans$answer_type != DNS_UPDATE )
		return;

	if ( ! c$dns?$query )
		c$dns$query = ans$query;

	c$dns$AA    = msg$AA;
	c$dns$RA    = msg$RA;

	if ( ! c$dns?$rtt )
		{
		c$dns$rtt = network_time() - c$dns$ts;



		if ( c$dns$rtt == 0secs )
			delete c$dns$rtt;
		}

	if ( reply != "" )
		{
		if ( msg$opcode == DNS_OP_DYNAMIC_UPDATE && ans$answer_type == DNS_UPDATE && ! starts_with(reply, "del:") )
			reply = fmt("add: %s", reply);

		if ( ! c$dns?$answers )
			c$dns$answers = vector();
		c$dns$answers += reply;

		if ( ! c$dns?$TTLs )
			c$dns$TTLs = vector();
		c$dns$TTLs += ans$TTL;
		}
	}

event dns_end(c: connection, msg: dns_msg) &priority=5
	{
	if ( ! c?$dns )
		return;

	if ( msg$QR )
		c$dns$saw_reply = T;
	else
		c$dns$saw_query = T;
	}

event dns_end(c: connection, msg: dns_msg) &priority=-5
	{
	if ( c?$dns && c$dns$saw_reply && c$dns$saw_query )
		{
		Log::write(DNS::LOG, c$dns);
		delete c$dns;
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
	{
	if ( msg$opcode != DNS_OP_QUERY && msg$opcode != DNS_OP_DYNAMIC_UPDATE && msg$opcode != DNS_OP_NOTIFY )

		return;

	c$dns$RD          = msg$RD;
	c$dns$TC          = msg$TC;
	c$dns$qclass      = qclass;
	c$dns$qclass_name = classes[qclass];
	c$dns$qtype       = qtype;
	c$dns$qtype_name  = query_types[qtype];
	c$dns$Z           = msg$Z;




	if ( c$id$resp_p == 137/udp )
		{
		local decoded_query = decode_netbios_name(query);

		if ( |decoded_query| != 0 )
			query = decoded_query;

		if ( c$dns$qtype_name == "SRV" )
			{


			c$dns$qtype_name = "NBSTAT";
			}
		}
	c$dns$query = query;
	}


event dns_unknown_reply(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, fmt("<unknown type=%s>", ans$qtype));
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
	{
	if ( msg$opcode == DNS_OP_DYNAMIC_UPDATE && ! msg$is_netbios )
		hook DNS::do_reply(c, msg, ans, fmt("A %s %s", ans$query, a));
	else
		hook DNS::do_reply(c, msg, ans, fmt("%s", a));
	}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec) &priority=5
	{
	local txt_strings: string = "";

	for ( i in strs )
		{
		if ( i > 0 )
			txt_strings += " ";

		txt_strings += fmt("TXT %d %s", |strs[i]|, strs[i]);
		}

	hook DNS::do_reply(c, msg, ans, txt_strings);
	}

event dns_SPF_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec) &priority=5
	{
	local spf_strings: string = "";

	for ( i in strs )
		{
		if ( i > 0 )
			spf_strings += " ";

		spf_strings += fmt("SPF %d %s", |strs[i]|, strs[i]);
		}

	hook DNS::do_reply(c, msg, ans, spf_strings);
	}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
	{
	if ( msg$opcode == DNS_OP_DYNAMIC_UPDATE && ! msg$is_netbios )
		hook DNS::do_reply(c, msg, ans, fmt("AAAA %s %s", ans$query, a));
	else
		hook DNS::do_reply(c, msg, ans, fmt("%s", a));
	}

event dns_A6_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
	{
	if ( msg$opcode == DNS_OP_DYNAMIC_UPDATE && ! msg$is_netbios )
		hook DNS::do_reply(c, msg, ans, fmt("A6 %s %s", ans$query, a));
	else
		hook DNS::do_reply(c, msg, ans, fmt("%s", a));
	}

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, name);
	}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, name);
	}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string,
                   preference: count) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, name);
	}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, name);
	}

event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, soa$mname);
	}

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, "");
	}

event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, target);
	}

event dns_NAPTR_reply(c: connection, msg: dns_msg, ans: dns_answer, naptr: dns_naptr_rr) &priority=5
	{

	local tmp = "";

	if ( |naptr$regexp| > 0 )
		tmp += naptr$regexp;

	if ( |naptr$replacement| > 0 )
		{
		if ( |tmp| > 0 )
			tmp += " ";

		tmp += naptr$replacement;
		}

	local r = fmt("NAPTR %s %s %s %s %s", naptr$order, naptr$preference, naptr$flags, naptr$service, tmp);

	hook DNS::do_reply(c, msg, ans, r);
	}





















event dns_RRSIG(c: connection, msg: dns_msg, ans: dns_answer, rrsig: dns_rrsig_rr) &priority=5
	{
	local s: string;
	s = fmt("RRSIG %s %s", rrsig$type_covered,
	        rrsig$signer_name == "" ? "<Root>" : rrsig$signer_name);
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_DNSKEY(c: connection, msg: dns_msg, ans: dns_answer, dnskey: dns_dnskey_rr) &priority=5
	{
	local s: string;
	s = fmt("DNSKEY %s", dnskey$algorithm);
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_NSEC(c: connection, msg: dns_msg, ans: dns_answer, next_name: string, bitmaps: string_vec) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, fmt("NSEC %s %s", ans$query, next_name));
	}

event dns_NSEC3(c: connection, msg: dns_msg, ans: dns_answer, nsec3: dns_nsec3_rr) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, "NSEC3");
	}

event dns_NSEC3PARAM(c: connection, msg: dns_msg, ans: dns_answer, nsec3param: dns_nsec3param_rr) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, "NSEC3PARAM");
	}

event dns_DS(c: connection, msg: dns_msg, ans: dns_answer, ds: dns_ds_rr) &priority=5
	{
	local s: string;
	s = fmt("DS %s %s", ds$algorithm, ds$digest_type);
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_BINDS(c: connection, msg: dns_msg, ans: dns_answer, binds: dns_binds_rr) &priority=5
	{
	hook DNS::do_reply(c, msg, ans, "BIND9 signing signal");
	}

event dns_SSHFP(c: connection, msg: dns_msg, ans: dns_answer, algo: count, fptype: count, fingerprint: string) &priority=5
	{
	local s: string;
	s = fmt("SSHFP: %s", bytestring_to_hexstr(fingerprint));
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_LOC(c: connection, msg: dns_msg, ans: dns_answer, loc: dns_loc_rr) &priority=5
	{
	local s: string;
	s = fmt("LOC:  %d %d %d", loc$size, loc$horiz_pre, loc$vert_pre);
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
	{
	if ( c?$dns )
		c$dns$rejected = T;
	}

event dns_dynamic_update_pre(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
	{
	local what: string;
	if ( ans$qclass == DNS::NONE && ans$qtype == DNS::ANY )

		what = fmt("NameNotInUse %s", ans$query);
	else if ( ans$qclass == DNS::ANY && ans$qtype == DNS::ANY )

		what = fmt("NameInUse %s", ans$query);
	else if ( ans$qclass == DNS::NONE)

		what = fmt("NoRRSet %s %s", query_types[ans$qtype], ans$query);
	else

		what = fmt("RRSetExists %s %s", query_types[ans$qtype], ans$query);

	local s: string = fmt("pre: %s", what);
	hook DNS::do_reply(c, msg, ans, s);
	}

event dns_dynamic_update_del(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
	{
	local what: string;

	if ( ans$qclass == DNS::ANY && ans$qtype == DNS::ANY )

		what = fmt("RRSet * %s", ans$query);
	else if ( ans$qclass == DNS::NONE )

		what = fmt("RR %s %s", query_types[ans$qtype], ans$query);
	else

		what = fmt("RRSet %s", query_types[ans$qtype]);

	local s: string = fmt("del: %s", what);
	hook DNS::do_reply(c, msg, ans, s);
	}

hook finalize_dns(c: connection)
	{
	if ( ! c?$dns_state )
		return;



	if( c$dns_state?$pending_query )
		Log::write(DNS::LOG, c$dns_state$pending_query);

	if( c$dns_state?$pending_queries )
		log_unmatched_msgs(c$dns_state$pending_queries);

	if( c$dns_state?$pending_replies )
		log_unmatched_msgs(c$dns_state$pending_replies);
	}
