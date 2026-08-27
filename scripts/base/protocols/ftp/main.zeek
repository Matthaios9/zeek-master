




@load ./info
@load ./utils
@load ./utils-commands
@load base/utils/paths
@load base/utils/numbers
@load base/utils/addrs
@load base/frameworks/cluster
@load base/frameworks/notice/weird
@load base/protocols/conn/removal-hooks

module FTP;

export {

	redef enum Log::ID += { LOG };


	const ports = { 21/tcp, 2811/tcp } &redef;


	global log_policy: Log::PolicyHook;


	option logged_commands = {
		"APPE", "DELE", "RETR", "STOR", "STOU", "ACCT", "PORT", "PASV", "EPRT",
		"EPSV"
	};


	option guest_ids = { "anonymous", "ftp", "ftpuser", "guest" };



	type ReplyCode: record {
		x: count;
		y: count;
		z: count;
	};


	global parse_ftp_reply_code: function(code: count): ReplyCode;



	global log_ftp: event(rec: Info);


	global finalize_ftp: Conn::RemovalHook;



	global finalize_ftp_data: hook(c: connection);




	option max_pending_commands = 20;




	option max_user_length = 128;




	option max_password_length = 128;



	option max_arg_length = 4096;



	option max_reply_msg_length = 4096;



	option log_at_least_one_command = T;
}


redef record connection += {
	ftp: Info &optional;
	ftp_data_reuse: bool &default=F;
};

event zeek_init() &priority=5
	{
	Log::create_stream(FTP::LOG, Log::Stream($columns=Info, $ev=log_ftp, $path="ftp", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_FTP, ports);
	}


global ftp_data_expected: table[addr, port] of Info &read_expire=5mins;

function minimize_info(info: Info): Info &is_used
	{



	local rval: Info;
	rval$ts = info$ts;
	rval$uid= info$uid;
	rval$id= info$id;
	rval$user = info$user;
	rval$passive = info$passive;
	rval$pending_commands = PendingCmds();
	return rval;
	}



const file_cmds = {
	"APPE", "CWD", "DELE", "MKD", "RETR", "RMD", "RNFR", "RNTO",
	"STOR", "STOU", "REST", "SIZE", "MDTM",
};



const directory_cmds = {
	["CWD",  250],
	["CDUP", 200],
	["CDUP", 250],
	["PWD",  257],
	["XPWD", 257],
};

function ftp_relay_topic(): string &is_used
	{
	local rval = Cluster::rr_topic(Cluster::proxy_pool, "ftp_transfer_rr_key");

	if ( rval == "" )

		return Cluster::manager_topic;

	return rval;
	}

function parse_ftp_reply_code(code: count): ReplyCode
	{
	local a: ReplyCode;

	a$z = code % 10;

	code = code / 10;
	a$y = code % 10;

	code = code / 10;
	a$x = code % 10;

	return a;
	}

function set_ftp_session(c: connection)
	{
	if ( ! c?$ftp )
		{
		local s: Info;
		s$ts=network_time();
		s$uid=c$uid;
		s$id=c$id;
		c$ftp=s;
		Conn::register_removal_hook(c, finalize_ftp);


		add_pending_cmd(c$ftp$pending_commands, ++c$ftp$command_seq, "<init>", "");
		}
	}

function should_hide_password(s: Info) : bool
	{
	return ! s$capture_password && to_lower(s$user) !in guest_ids;
	}

function ftp_message(c: connection)
	{
	if ( ! c?$ftp ) return;
	local password_hidden_string = "<hidden>";
	local s: Info = c$ftp;
	s$ts=s$cmdarg$ts;
	s$command=s$cmdarg$cmd;

	s$arg = s$cmdarg$arg;
	if ( s$cmdarg$cmd in file_cmds )
		s$arg = build_url_ftp(s);


	if ( |s$arg| > max_arg_length )
		{
		Reporter::conn_weird("FTP_arg_too_long", c, cat(|s$arg|), "FTP");
		s$arg = s$arg[:max_arg_length];
		}

	if ( s?$reply_msg && |s$reply_msg| > max_reply_msg_length )
		{
		Reporter::conn_weird("FTP_reply_msg_too_long", c, cat(|s$reply_msg|), "FTP");
		s$reply_msg = s$reply_msg[:max_reply_msg_length];
		}


	if ( s$command == "PASS" && should_hide_password(s))
		s$arg = password_hidden_string;

	if ( s$arg == "" )
		delete s$arg;

	if ( s?$password && should_hide_password(s))
		s$password = password_hidden_string;

	if ( s?$cmdarg && s$command in logged_commands)
		{
		Log::write(FTP::LOG, s);
		c$ftp$logged_command_seen = T;
		}




	delete s$mime_type;
	delete s$file_size;
	delete s$data_channel;
	delete s$fuid;
	}

event sync_add_expected_data(s: Info, chan: ExpectedDataChannel) &is_used
	{
@if ( Cluster::local_node_type() == Cluster::PROXY ||
      Cluster::local_node_type() == Cluster::MANAGER )
	Cluster::publish(Cluster::worker_topic, sync_add_expected_data, minimize_info(s), chan);
@else
	ftp_data_expected[chan$resp_h, chan$resp_p] = s;
	Analyzer::schedule_analyzer(chan$orig_h, chan$resp_h, chan$resp_p,
	                            Analyzer::ANALYZER_FTP_DATA,
	                            5mins);
@endif
	}

event sync_remove_expected_data(resp_h: addr, resp_p: port) &is_used
	{
@if ( Cluster::local_node_type() == Cluster::PROXY ||
      Cluster::local_node_type() == Cluster::MANAGER )
	Cluster::publish(Cluster::worker_topic, sync_remove_expected_data, resp_h, resp_p);
@else
	delete ftp_data_expected[resp_h, resp_p];
@endif
	}

function add_expected_data_channel(s: Info, chan: ExpectedDataChannel)
	{
	s$passive = chan$passive;
	s$data_channel = chan;
	ftp_data_expected[chan$resp_h, chan$resp_p] = s;
	Analyzer::schedule_analyzer(chan$orig_h, chan$resp_h, chan$resp_p,
	                            Analyzer::ANALYZER_FTP_DATA,
	                            5mins);
@if ( Cluster::is_enabled() )
	Cluster::publish(ftp_relay_topic(), sync_add_expected_data, minimize_info(s), chan);
@endif
	}

event ftp_request(c: connection, command: string, arg: string) &priority=5
	{





	if ( c?$ftp && c$ftp?$cmdarg && c$ftp?$reply_code )
		{
		if ( remove_pending_cmd(c$ftp$pending_commands, c$ftp$cmdarg) )
			ftp_message(c);
		}

	local id = c$id;
	set_ftp_session(c);


	if ( |c$ftp$pending_commands| < max_pending_commands )
		add_pending_cmd(c$ftp$pending_commands, ++c$ftp$command_seq, command, arg);
	else
		Reporter::conn_weird("FTP_too_many_pending_commands", c,
				     cat(|c$ftp$pending_commands|), "FTP");

	if ( command == "USER" )
		{
		if ( |arg| > max_user_length )
			{
			Reporter::conn_weird("FTP_user_too_long", c, cat(|arg|), "FTP");
			arg = arg[:max_user_length];
			}

		c$ftp$user = arg;
		}
	else if ( command == "PASS" )
		{
		if ( |arg| > max_password_length )
			{
			Reporter::conn_weird("FTP_password_too_long", c, cat(|arg|), "FTP");
			arg = arg[:max_password_length];
			}

		c$ftp$password = arg;
		}
	else if ( command == "PORT" || command == "EPRT" )
		{
		local data = (command == "PORT") ?
				parse_ftp_port(arg) : parse_eftp_port(arg);

		if ( data$valid )
			{
			add_expected_data_channel(c$ftp, ExpectedDataChannel($passive=F, $orig_h=id$resp_h,
			                                                     $resp_h=data$h, $resp_p=data$p));
			}
		else
			{

			}
		}
	}


event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) &priority=5
	{
	set_ftp_session(c);

































	if ( cont_resp && code == 0 && c$ftp?$reply_code )
		{
		if ( /^[1-9][0-9]{2} [[:print:]]{10}.*/ !in msg )
			return;
		else
			{



			}
		}

	c$ftp$cmdarg = get_pending_cmd(c$ftp$pending_commands, code, msg);
	c$ftp$reply_code = code;
	c$ftp$reply_msg = msg;


	if ( cont_resp )
		return;







	if ( (code == 150 && c$ftp$cmdarg$cmd == "RETR") ||
	     (code == 213 && c$ftp$cmdarg$cmd == "SIZE") )
		{




		c$ftp$file_size = extract_count(msg, F);
		}


	else if ( (code == 227 || code == 229) &&
	          (c$ftp$cmdarg$cmd == "PASV" || c$ftp$cmdarg$cmd == "EPSV") )
		{
		local data = (code == 227) ? parse_ftp_pasv(msg) : parse_ftp_epsv(msg);

		if ( data$valid )
			{
			c$ftp$passive=T;

			if ( code == 229 && data$h == [::] )
				data$h = c$id$resp_h;

			add_expected_data_channel(c$ftp, ExpectedDataChannel($passive=T, $orig_h=c$id$orig_h,
			                                                     $resp_h=data$h, $resp_p=data$p));
			}
		else
			{

			}
		}

	if ( [c$ftp$cmdarg$cmd, code] in directory_cmds && ! c$ftp$cmdarg$cwd_consumed )
		{
		c$ftp$cmdarg$cwd_consumed = T;

		if ( c$ftp$cmdarg$cmd == "CWD" )
			c$ftp$cwd = build_path_compressed(c$ftp$cwd, c$ftp$cmdarg$arg);

		else if ( c$ftp$cmdarg$cmd == "CDUP" )
			c$ftp$cwd = build_path_compressed(c$ftp$cwd, "/..");

		else if ( c$ftp$cmdarg$cmd == "PWD" || c$ftp$cmdarg$cmd == "XPWD" )
			c$ftp$cwd = extract_path(msg);
		}




	if ( |c$ftp$pending_commands| > 1 )
		{
		remove_pending_cmd(c$ftp$pending_commands, c$ftp$cmdarg);
		ftp_message(c);
		}
	}

event scheduled_analyzer_applied(c: connection, a: Analyzer::Tag) &priority=10
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in ftp_data_expected )
		{
		add c$service["ftp-data"];
		Conn::register_removal_hook(c, finalize_ftp_data);
		}
	}

event file_transferred(c: connection, prefix: string, descr: string,
			mime_type: string) &priority=5
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in ftp_data_expected )
		{
		local s = ftp_data_expected[id$resp_h, id$resp_p];
		s$mime_type = split_string1(mime_type, /;/)[0];
		}
	}

event connection_reused(c: connection) &priority=5
	{
	if ( "ftp-data" in c$service )
		c$ftp_data_reuse = T;
	}

hook finalize_ftp_data(c: connection)
	{
	if ( c$ftp_data_reuse ) return;
	if ( [c$id$resp_h, c$id$resp_p] in ftp_data_expected )
		{
		delete ftp_data_expected[c$id$resp_h, c$id$resp_p];
@if ( Cluster::is_enabled() )
		Cluster::publish(ftp_relay_topic(), sync_remove_expected_data, c$id$resp_h, c$id$resp_p);
@endif
		}
	}


hook finalize_ftp(c: connection)
	{
	if ( ! c?$ftp ) return;

	for ( _, cmdarg in c$ftp$pending_commands )
		{
		c$ftp$cmdarg = cmdarg;
		ftp_message(c);
		}

	if ( c$ftp?$user && ! c$ftp$logged_command_seen && log_at_least_one_command )
		{
		local s: Info = c$ftp;
		Log::write(FTP::LOG, s);
		}
	}
