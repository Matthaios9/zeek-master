

@load ./consts
@load base/protocols/conn/removal-hooks

module MySQL;

export {
	redef enum Log::ID += { mysql::LOG };


	const ports = { 1434/tcp, 3306/tcp } &redef;

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts:     time    &log;

		uid:    string  &log;

		id:     conn_id &log;

		cmd:	string	&log;

		arg:	string	&log;

		success: bool &log &optional;

		rows: count &log &optional;

		response: string &log &optional;
	};



	global log_mysql: event(rec: Info);


	global finalize_mysql: Conn::RemovalHook;
}

redef record connection += {
	mysql: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(mysql::LOG, Log::Stream($columns=Info, $ev=log_mysql, $path="mysql", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_MYSQL, ports);
	}

event mysql_handshake(c: connection, username: string)
	{
	if ( ! c?$mysql )
		{
		local info: Info;
		info$ts = network_time();
		info$uid = c$uid;
		info$id = c$id;
		info$cmd = "login";
		info$arg = username;
		c$mysql = info;
		Conn::register_removal_hook(c, finalize_mysql);
		}
	}

event mysql_command_request(c: connection, command: count, arg: string) &priority=5
	{
	if ( c?$mysql )
		{


		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}

	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;
	info$cmd = commands[command];
	info$arg = sub(arg, /\0$/, "");
	c$mysql = info;
	Conn::register_removal_hook(c, finalize_mysql);
	}

event mysql_change_user(c: connection, username: string) &priority=5
	{
	c$mysql$arg = username;
	}

event mysql_command_request(c: connection, command: count, arg: string) &priority=-5
	{
	if ( c?$mysql && c$mysql?$cmd && c$mysql$cmd == "quit" )
		{

		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}

event mysql_error(c: connection, code: count, msg: string) &priority=5
	{
	if ( c?$mysql )
		{
		c$mysql$success = F;
		c$mysql$response = msg;
		}
	}

event mysql_error(c: connection, code: count, msg: string) &priority=-5
	{
	if ( c?$mysql )
		{
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}

event mysql_eof(c: connection, is_intermediate: bool) &priority=-5
	{
	if ( is_intermediate )
		return;

	if ( c?$mysql )
		{


		if ( ! c$mysql?$success )
			c$mysql$success = T;
		if ( ! c$mysql?$rows )
			c$mysql$rows = 0;

		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}

event mysql_ok(c: connection, affected_rows: count) &priority=5
	{
	if ( c?$mysql )
		{
		c$mysql$success = T;
		c$mysql$rows = affected_rows;
		}
	}

event mysql_ok(c: connection, affected_rows: count) &priority=-5
	{
	if ( c?$mysql )
		{
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}

hook finalize_mysql(c: connection)
	{
	if ( c?$mysql )
		{
		Log::write(mysql::LOG, c$mysql);
		delete c$mysql;
		}
	}
