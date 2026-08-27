@load base/protocols/conn/removal-hooks

module NTLM;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts         : time     &log;

		uid        : string   &log;

		id         : conn_id  &log;


		username   : string   &log &optional;

		hostname   : string   &log &optional;

		domainname : string   &log &optional;


		server_nb_computer_name: string &log &optional;

		server_dns_computer_name: string &log &optional;

		server_tree_name: string &log &optional;


		success    : bool     &log &optional;



		done: bool  &default=F;
	};


	global finalize_ntlm: Conn::RemovalHook;
}

redef DPD::ignore_violations += { Analyzer::ANALYZER_NTLM };

redef record connection += {
	ntlm: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(NTLM::LOG, Log::Stream($columns=Info, $path="ntlm", $policy=log_policy));
	}

function set_session(c: connection)
	{
	if ( ! c?$ntlm )
		{
		c$ntlm = NTLM::Info($ts=network_time(), $uid=c$uid, $id=c$id);
		Conn::register_removal_hook(c, finalize_ntlm);
		}
	}

event ntlm_negotiate(c: connection, request: NTLM::Negotiate) &priority=5
	{
	set_session(c);
	}

event ntlm_challenge(c: connection, challenge: NTLM::Challenge) &priority=5
	{
	set_session(c);

	if ( challenge?$target_info )
		{
		local ti = challenge$target_info;
		if ( ti?$nb_computer_name )
			c$ntlm$server_nb_computer_name = ti$nb_computer_name;
		if ( ti?$dns_computer_name )
			c$ntlm$server_dns_computer_name = ti$dns_computer_name;
		if ( ti?$dns_tree_name )
			c$ntlm$server_tree_name = ti$dns_tree_name;
		}
	}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate) &priority=5
	{
	set_session(c);

	if ( request?$domain_name )
		c$ntlm$domainname = request$domain_name;
	if ( request?$workstation )
		c$ntlm$hostname = request$workstation;
	if ( request?$user_name )
		c$ntlm$username = request$user_name;
	}

event gssapi_neg_result(c: connection, state: count) &priority=3
	{

	if ( c?$ntlm && state != 1 )
		c$ntlm$success = (state == 0);
	}

event gssapi_neg_result(c: connection, state: count) &priority=-3
	{
	if ( c?$ntlm && ! c$ntlm$done )
		{

		if ( c$ntlm?$success )
			{
			Log::write(NTLM::LOG, c$ntlm);
			c$ntlm$done = T;
			}
		}
	}

hook finalize_ntlm(c: connection)
	{
	if ( c?$ntlm && ! c$ntlm$done )
		{
		Log::write(NTLM::LOG, c$ntlm);
		}
	}
