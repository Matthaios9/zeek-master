@load base/protocols/conn/removal-hooks

module RFB;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;


	type Info: record {

		ts:     time    &log;

		uid:    string  &log;

		id:     conn_id &log;


		client_major_version: string &log &optional;

		client_minor_version: string &log &optional;

		server_major_version: string &log &optional;

		server_minor_version: string &log &optional;


		authentication_method: string &log &optional;

		auth: bool &log &optional;


		share_flag: bool &log &optional;

		desktop_name: string &log &optional;

		width: count &log &optional;

		height: count &log &optional;



		done: bool  &default=F;
	};

	global log_rfb: event(rec: Info);


	global finalize_rfb: Conn::RemovalHook;
}

function friendly_auth_name(auth: count): string
	{
	switch (auth) {
		case 0:
			return "Invalid";
		case 1:
			return "None";
		case 2:
			return "VNC";
		case 16:
			return "Tight";
		case 17:
			return "Ultra";
		case 18:
			return "TLS";
		case 19:
			return "VeNCrypt";
		case 20:
			return "GTK-VNC SASL";
		case 21:
			return "MD5 hash authentication";
		case 22:
			return "Colin Dean xvp";
		case 30:
			return "Apple Remote Desktop";
	}
	return "RealVNC";
}

redef record connection += {
	rfb: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(RFB::LOG, Log::Stream($columns=Info, $ev=log_rfb, $path="rfb", $policy=log_policy));
	}

function write_log(c:connection)
	{
	local state = c$rfb;
	if ( state$done )
		{
		return;
		}

	Log::write(RFB::LOG, c$rfb);
	c$rfb$done = T;
	}

function set_session(c: connection)
	{
	if ( ! c?$rfb )
		{
		local info: Info;
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;

		c$rfb = info;
		Conn::register_removal_hook(c, finalize_rfb);
		}
	}

event rfb_client_version(c: connection, major_version: string, minor_version: string) &priority=5
	{
	set_session(c);
	c$rfb$client_major_version = major_version;
	c$rfb$client_minor_version = minor_version;
	}

event rfb_server_version(c: connection, major_version: string, minor_version: string) &priority=5
	{
	set_session(c);
	c$rfb$server_major_version = major_version;
	c$rfb$server_minor_version = minor_version;
	}

event rfb_authentication_type(c: connection, authtype: count) &priority=5
	{
	set_session(c);

	c$rfb$authentication_method = friendly_auth_name(authtype);
	}

event rfb_server_parameters(c: connection, name: string, width: count, height: count) &priority=5
	{
	set_session(c);

	c$rfb$desktop_name = name;
	c$rfb$width = width;
	c$rfb$height = height;
	}

event rfb_server_parameters(c: connection, name: string, width: count, height: count) &priority=-5
	{
	write_log(c);
	}

event rfb_authentication_result(c: connection, result: bool) &priority=5
	{
	c$rfb$auth = result;
	}

event rfb_share_flag(c: connection, flag: bool) &priority=5
	{
	c$rfb$share_flag = flag;
	}

hook finalize_rfb(c: connection)
	{
	if ( c?$rfb )
		{
		write_log(c);
		}
	}
