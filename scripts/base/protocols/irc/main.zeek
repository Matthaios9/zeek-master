



module IRC;

export {
	redef enum Log::ID += { LOG };


	const ports = { 6666/tcp, 6667/tcp, 6668/tcp, 6669/tcp } &redef;

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts:       time        &log;

		uid:      string      &log;

		id:       conn_id     &log;

		nick:     string      &log &optional;

		user:     string      &log &optional;


		command:  string      &log &optional;

		value:    string      &log &optional;

		addl:     string      &log &optional;
	};



	global irc_log: event(rec: Info);
}

redef record connection += {

	irc:  Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(IRC::LOG, Log::Stream($columns=Info, $ev=irc_log, $path="irc", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_IRC, ports);
	}

function new_session(c: connection): Info
	{
	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;
	return info;
	}

function set_session(c: connection)
	{
	if ( ! c?$irc )
		c$irc = new_session(c);

	c$irc$ts=network_time();
	}

event irc_nick_message(c: connection, is_orig: bool, who: string, newnick: string) &priority=5
	{
	set_session(c);
	if ( is_orig )
		{
		c$irc$command = "NICK";
		c$irc$value = newnick;
		}
	}

event irc_nick_message(c: connection, is_orig: bool, who: string, newnick: string) &priority=-5
	{
	if ( is_orig )
		{
		Log::write(IRC::LOG, c$irc);
		c$irc$nick  = newnick;
		}
	}

event irc_user_message(c: connection, is_orig: bool, user: string, host: string, server: string, real_name: string) &priority=5
	{
	set_session(c);
	if ( is_orig )
		{
		c$irc$command = "USER";
		c$irc$value = user;
		c$irc$addl=fmt("%s %s %s", host, server, real_name);
		}
	}

event irc_user_message(c: connection, is_orig: bool, user: string, host: string, server: string, real_name: string) &priority=-5
	{
	if ( is_orig )
		{
		Log::write(IRC::LOG, c$irc);
		c$irc$user = user;
		}
	}

event irc_join_message(c: connection, is_orig: bool, info_list: irc_join_list) &priority=5
	{
	set_session(c);
	if ( is_orig )
		c$irc$command = "JOIN";
	}

event irc_join_message(c: connection, is_orig: bool, info_list: irc_join_list) &priority=-5
	{
	if ( is_orig )
		{
		for ( l in info_list )
			{
			c$irc$value = l$channel;
			c$irc$addl = (l$password != "" ? fmt(" with channel key: '%s'", l$password) : "");
			Log::write(IRC::LOG, c$irc);
			}
		}
	}
