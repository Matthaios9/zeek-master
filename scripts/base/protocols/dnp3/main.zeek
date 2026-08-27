

@load ./consts
@load base/protocols/conn/removal-hooks

module DNP3;

export {
	redef enum Log::ID += { LOG };


	const ports = { 20000/tcp, 20000/udp } &redef;

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts:         time           &log;

		uid:        string         &log;

		id:         conn_id        &log;

		fc_request: string         &log &optional;

		fc_reply:   string         &log &optional;

		iin:        count          &log &optional;
	};



	global log_dnp3: event(rec: Info);


	global finalize_dnp3: Conn::RemovalHook;
}

redef record connection += {
	dnp3: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(DNP3::LOG, Log::Stream($columns=Info, $ev=log_dnp3, $path="dnp3", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_DNP3_TCP, ports);
	}

event dnp3_application_request_header(c: connection, is_orig: bool, application_control: count, fc: count)
	{
	if ( ! c?$dnp3 )
		{
		c$dnp3 = Info($ts=network_time(), $uid=c$uid, $id=c$id);
		Conn::register_removal_hook(c, finalize_dnp3);
		}

	c$dnp3$ts = network_time();
	c$dnp3$fc_request = function_codes[fc];
	}

event dnp3_application_response_header(c: connection, is_orig: bool, application_control: count, fc: count, iin: count)
	{
	if ( ! c?$dnp3 )
		{
		c$dnp3 = Info($ts=network_time(), $uid=c$uid, $id=c$id);
		Conn::register_removal_hook(c, finalize_dnp3);
		}

	c$dnp3$ts = network_time();
	c$dnp3$fc_reply = function_codes[fc];
	c$dnp3$iin = iin;

	Log::write(LOG, c$dnp3);

	delete c$dnp3;
	}

hook finalize_dnp3(c: connection)
	{
	if ( ! c?$dnp3 )
		return;

	Log::write(LOG, c$dnp3);
	delete c$dnp3;
	}
