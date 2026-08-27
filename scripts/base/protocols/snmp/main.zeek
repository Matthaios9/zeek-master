

@load base/protocols/conn/removal-hooks

module SNMP;

export {
	redef enum Log::ID += { LOG };


	const ports = { 161/udp, 162/udp } &redef;

	global log_policy: Log::PolicyHook;


	type Info: record {

		ts: time &log;

		uid: string &log;


		id: conn_id &log;


		duration: interval &log &default=0secs;

		version: string &log;





		community: string &log &optional;



		get_requests:      count &log &default=0;


		get_bulk_requests: count &log &default=0;


		get_responses:     count &log &default=0;


		set_requests: count &log &default=0;


		display_string: string &log &optional;


		up_since: time &log &optional;
	};


	const version_map: table[count] of string = {
		[0] = "1",
		[1] = "2c",
		[3] = "3",
	} &redef &default="unknown";



	global log_snmp: event(rec: Info);


	global finalize_snmp: Conn::RemovalHook;
}

redef record connection += {
	snmp: SNMP::Info &optional;
};

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SNMP, ports);
	Log::create_stream(SNMP::LOG, Log::Stream($columns=SNMP::Info, $ev=log_snmp, $path="snmp", $policy=log_policy));
	}

function init_state(c: connection, h: SNMP::Header): Info
	{
	if ( ! c?$snmp )
		{
		c$snmp = Info($ts=network_time(),
		              $uid=c$uid, $id=c$id,
		              $version=version_map[h$version]);
		Conn::register_removal_hook(c, finalize_snmp);
		}

	local s = c$snmp;

	if ( ! s?$community )
		{
		if ( h?$v1 )
			s$community = h$v1$community;
		else if ( h?$v2 )
			s$community = h$v2$community;
		else if ( h?$v3 && h$v3?$user_security_parameters && |h$v3$user_security_parameters$UserName| > 0 )
			s$community = h$v3$user_security_parameters$UserName;
		}

	s$duration = network_time() - s$ts;
	return s;
	}

hook finalize_snmp(c: connection)
	{
	if ( c?$snmp )
		Log::write(LOG, c$snmp);
	}

event snmp_get_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);
	s$get_requests += |pdu$bindings|;
	}

event snmp_get_bulk_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::BulkPDU) &priority=5
	{
	local s = init_state(c, header);
	s$get_bulk_requests += |pdu$bindings|;
	}

event snmp_get_next_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);
	s$get_requests += |pdu$bindings|;
	}

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);
	s$get_responses += |pdu$bindings|;

	for ( i in pdu$bindings )
		{
		local binding = pdu$bindings[i];

		if ( binding$oid == "1.3.6.1.2.1.1.1.0" && binding$value?$octets )
			c$snmp$display_string = binding$value$octets;
		else if ( binding$oid == "1.3.6.1.2.1.1.3.0" && binding$value?$unsigned )
			{
			local up_seconds = binding$value$unsigned / 100.0;
			s$up_since = network_time() - (up_seconds as interval);
			}
		}
	}

event snmp_set_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	local s = init_state(c, header);
	s$set_requests += |pdu$bindings|;
	}

event snmp_trap(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::TrapPDU) &priority=5
	{
	init_state(c, header);
	}

event snmp_inform_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	init_state(c, header);
	}

event snmp_trapV2(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	init_state(c, header);
	}

event snmp_report(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=5
	{
	init_state(c, header);
	}

event snmp_unknown_pdu(c: connection, is_orig: bool, header: SNMP::Header, tag: count) &priority=5
	{
	init_state(c, header);
	}

event snmp_unknown_scoped_pdu(c: connection, is_orig: bool, header: SNMP::Header, tag: count) &priority=5
	{
	init_state(c, header);
	}

event snmp_encrypted_pdu(c: connection, is_orig: bool, header: SNMP::Header) &priority=5
	{
	init_state(c, header);
	}
