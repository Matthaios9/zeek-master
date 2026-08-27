@load base/frameworks/tunnels
@load ./consts
@load base/protocols/conn/removal-hooks

module SOCKS;

export {
	redef enum Log::ID += { LOG };


	const ports = { 1080/tcp } &redef;

	global log_policy: Log::PolicyHook;


	option default_capture_password = F;


	type Info: record {

		ts:               time            &log;


		uid:              string          &log;

		id:               conn_id         &log;

		version:          count           &log;

		user:             string          &log &optional;

		password:         string          &log &optional;

		status:           string          &log &optional;


		request:          SOCKS::Address  &log &optional;

		request_p:        port            &log &optional;

		bound:            SOCKS::Address  &log &optional;

		bound_p:          port            &log &optional;

		capture_password: bool            &default=default_capture_password;
	};



	global log_socks: event(rec: Info);


	global finalize_socks: Conn::RemovalHook;
}

event zeek_init() &priority=5
	{
	Log::create_stream(SOCKS::LOG, Log::Stream($columns=Info, $ev=log_socks, $path="socks", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_SOCKS, ports);
	}

redef record connection += {
	socks: SOCKS::Info &optional;
};

function set_session(c: connection, version: count)
	{
	if ( ! c?$socks )
		{
		c$socks = Info($ts=network_time(), $id=c$id, $uid=c$uid, $version=version);
		Conn::register_removal_hook(c, finalize_socks);
		}
	}

event socks_request(c: connection, version: count, request_type: count,
                    sa: SOCKS::Address, p: port, user: string) &priority=5
	{
	set_session(c, version);

	c$socks$request   = sa;
	c$socks$request_p = p;




	local cid = copy(c$id);
	cid$orig_p = 0/tcp;
	Tunnel::register(Tunnel::EncapsulatingConn($cid=cid, $tunnel_type=Tunnel::SOCKS));
	}

event socks_reply(c: connection, version: count, reply: count, sa: SOCKS::Address, p: port) &priority=5
	{
	set_session(c, version);

	if ( version == 5 )
		c$socks$status = v5_status[reply];
	else if ( version == 4 )
		c$socks$status = v4_status[reply];

	c$socks$bound   = sa;
	c$socks$bound_p = p;
	}

event socks_login_userpass_request(c: connection, user: string, password: string) &priority=5
	{

	set_session(c, 5);

	c$socks$user = user;

	if ( c$socks$capture_password )
		c$socks$password = password;
	}

event socks_login_userpass_reply(c: connection, code: count) &priority=5
	{

	set_session(c, 5);

	c$socks$status = v5_status[code];
	}

hook finalize_socks(c: connection)
	{


	if ( "SOCKS" in c$service )
		Log::write(SOCKS::LOG, c$socks);
	}
