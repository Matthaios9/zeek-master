

module Modbus;

@load ./consts

export {
	redef enum Log::ID += { LOG };


	const ports = { 502/tcp } &redef;

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts:        time           &log;

		uid:       string         &log;

		id:        conn_id        &log;

		tid:	   count         &log &optional;

		unit:	   count         &log &optional;

		func:      string         &log &optional;

		pdu_type:  string         &log &optional;

		exception: string         &log &optional;
	};



	global log_modbus: event(rec: Info);
}

redef record connection += {
	modbus: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(Modbus::LOG, Log::Stream($columns=Info, $ev=log_modbus, $path="modbus", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_MODBUS, ports);
	}

function build_func(func: count): string
	{
	local masked = func & ~0x80;




	if ( func in function_codes || masked !in function_codes )
	        return function_codes[func];

	local s = function_codes[masked];


	if ( func & 0x80 == 0x80 )
	        s += "_EXCEPTION";

	return s;
	}

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) &priority=5
	{
	if ( ! c?$modbus )
		{
		c$modbus = Info($ts=network_time(), $uid=c$uid, $id=c$id);
		}

	c$modbus$ts   = network_time();
	c$modbus$tid = headers$tid;
	c$modbus$unit = headers$uid;
	c$modbus$func = build_func(headers$function_code);


	c$modbus$pdu_type = is_orig ? "REQ" : "RESP";
	}

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) &priority=-5
	{

	if ( headers$function_code < 0x80 )
		Log::write(LOG, c$modbus);
	}

event modbus_exception(c: connection, headers: ModbusHeaders, code: count) &priority=5
	{
	c$modbus$exception = exception_codes[code];
	}

event modbus_exception(c: connection, headers: ModbusHeaders, code: count) &priority=-5
	{
	Log::write(LOG, c$modbus);
	delete c$modbus$exception;
	}
