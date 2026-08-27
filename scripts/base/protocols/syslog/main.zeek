


@load ./consts

module Syslog;

export {
	redef enum Log::ID += { LOG };


	const ports = { 514/udp } &redef;
	const tcp_ports = { 514/tcp } &redef;

	global log_policy: Log::PolicyHook;


	type Info: record {

		ts:        time            &log;

		uid:       string          &log;

		id:        conn_id         &log;

		proto:     transport_proto &log;

		facility:  string          &log;

		severity:  string          &log;

		message:   string          &log;
	};
}

redef record connection += {
	syslog: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(Syslog::LOG, Log::Stream($columns=Info, $path="syslog", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_SYSLOG, ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SYSLOG_TCP, tcp_ports);
	}

event syslog_message(c: connection, facility: count, severity: count, msg: string) &priority=5
	{
	local info: Info;
	info$ts=network_time();
	info$uid=c$uid;
	info$id=c$id;
	info$proto=get_port_transport_proto(c$id$resp_p);
	info$facility=facility_codes[facility];
	info$severity=severity_codes[severity];
	info$message=msg;

	c$syslog = info;
	}

event syslog_message(c: connection, facility: count, severity: count, msg: string) &priority=-5
	{
	Log::write(Syslog::LOG, c$syslog);
	}
