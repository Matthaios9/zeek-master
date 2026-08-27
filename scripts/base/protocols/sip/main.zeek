



@load base/utils/numbers
@load base/utils/files
@load base/protocols/conn/removal-hooks

module SIP;

export {
	redef enum Log::ID += { LOG };


	const ports = { 5060/udp } &redef;

	global log_policy: Log::PolicyHook;


	type Info: record {

		ts:                      time              &log;

		uid:                     string            &log;

		id:                      conn_id           &log;


		trans_depth:             count             &log;

		method:                  string            &log &optional;

		uri:                     string            &log &optional;

		date:                    string            &log &optional;



		request_from:            string            &log &optional;

		request_to:              string            &log &optional;



		response_from:            string            &log &optional;

		response_to:              string            &log &optional;


		reply_to:                string            &log &optional;

		call_id:                 string            &log &optional;

		seq:                     string            &log &optional;

		subject:                 string            &log &optional;

		request_path:            vector of string  &log &optional;

		response_path:           vector of string  &log &optional;

		user_agent:              string            &log &optional;

		status_code:             count             &log &optional;

		status_msg:              string            &log &optional;

		warning:                 string            &log &optional;

		request_body_len:        count             &log &optional;

		response_body_len:       count             &log &optional;

		content_type:            string            &log &optional;
	};

	type State: record {

		pending:          table[count] of Info;

		current_request:  count                &default=0;

		current_response: count                &default=0;
	};




	option sip_methods: set[string] = {
		"REGISTER", "INVITE", "ACK", "CANCEL", "BYE", "OPTIONS", "NOTIFY", "SUBSCRIBE"
	};



	global log_sip: event(rec: Info);


	global finalize_sip: Conn::RemovalHook;
}


redef record connection += {
	sip:        Info  &optional;
	sip_state:  State &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(SIP::LOG, Log::Stream($columns=Info, $ev=log_sip, $path="sip", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_SIP, ports);
	}

function new_sip_session(c: connection): Info
	{
	local tmp: Info;
	tmp$ts=network_time();
	tmp$uid=c$uid;
	tmp$id=c$id;


	tmp$trans_depth = c$sip_state$current_request;

	tmp$request_path = vector();
	tmp$response_path = vector();

	return tmp;
	}

function set_state(c: connection, is_request: bool)
	{
	if ( ! c?$sip_state )
		{
		local s: State;
		c$sip_state = s;
		Conn::register_removal_hook(c, finalize_sip);
		}

	if ( is_request )
		{
		if ( c$sip_state$current_request !in c$sip_state$pending )
			c$sip_state$pending[c$sip_state$current_request] = new_sip_session(c);

		c$sip = c$sip_state$pending[c$sip_state$current_request];
		}
	else
		{
		if ( c$sip_state$current_response !in c$sip_state$pending )
			c$sip_state$pending[c$sip_state$current_response] = new_sip_session(c);

		c$sip = c$sip_state$pending[c$sip_state$current_response];
		}
	}

function flush_pending(c: connection)
	{

	if ( c?$sip_state )
		{
		for ( r, info in c$sip_state$pending )
			{

			if ( r == 0 )
				next;

			Log::write(SIP::LOG, info);
			}
		}
	}

event sip_request(c: connection, method: string, original_URI: string, version: string) &priority=5
	{
	set_state(c, T);

	c$sip$method = method;
	c$sip$uri = original_URI;

	if ( method !in sip_methods )
		Reporter::conn_weird("unknown_SIP_method", c, method);
	}

event sip_reply(c: connection, version: string, code: count, reason: string) &priority=5
	{
	set_state(c, F);

	if ( c$sip_state$current_response !in c$sip_state$pending &&
	     (code < 100 && 200 <= code) )
		++c$sip_state$current_response;

	c$sip$status_code = code;
	c$sip$status_msg = reason;
	}

event sip_header(c: connection, is_request: bool, name: string, value: string) &priority=5
	{
	if ( ! c?$sip_state )
		{
		local s: State;
		c$sip_state = s;
		Conn::register_removal_hook(c, finalize_sip);
		}

	if ( is_request )
		{
		if ( c$sip_state$current_request !in c$sip_state$pending )
			++c$sip_state$current_request;
		set_state(c, is_request);
		switch ( name )
			{
			case "CALL-ID":
				c$sip$call_id = value;
				break;
			case "CONTENT-LENGTH", "L":
				if ( value ?as count )
					c$sip$request_body_len = value as count;
				else
					Reporter::conn_weird("invalid_SIP_request_body_len", c, value);
				break;
			case "CSEQ":
				c$sip$seq = value;
				break;
			case "DATE":
				c$sip$date = value;
				break;
			case "FROM", "F":
				c$sip$request_from = split_string1(value, /;[ ]?tag=/)[0];
				break;
			case "REPLY-TO":
				c$sip$reply_to = value;
				break;
			case "SUBJECT", "S":
				c$sip$subject = value;
				break;
			case "TO", "T":
				c$sip$request_to = value;
				break;
			case "USER-AGENT":
				c$sip$user_agent = value;
				break;
			case "VIA", "V":
				c$sip$request_path += split_string1(value, /;[ ]?branch/)[0];
				break;
			}

		c$sip_state$pending[c$sip_state$current_request] = c$sip;
		}
	else
		{
		if ( c$sip_state$current_response !in c$sip_state$pending )
			++c$sip_state$current_response;

		set_state(c, is_request);
		switch ( name )
			{
			case "CONTENT-LENGTH", "L":
				if ( value ?as count )
					c$sip$response_body_len = value as count;
				else
					Reporter::conn_weird("invalid_SIP_response_body_len", c, value);
				break;
			case "CONTENT-TYPE", "C":
				c$sip$content_type = value;
				break;
			case "WARNING":
				c$sip$warning = value;
				break;
			case "FROM", "F":
				c$sip$response_from = split_string1(value, /;[ ]?tag=/)[0];
				break;
			case "TO", "T":
				c$sip$response_to = value;
				break;
			case "VIA", "V":
				c$sip$response_path += split_string1(value, /;[ ]?branch/)[0];
				break;
			}

		c$sip_state$pending[c$sip_state$current_response] = c$sip;
		}
	}

event sip_end_entity(c: connection, is_request: bool) &priority = 5
	{
	set_state(c, is_request);
	}

event sip_end_entity(c: connection, is_request: bool) &priority = -5
	{

	if ( ! is_request )
		{
		Log::write(SIP::LOG, c$sip);

		if ( c$sip$status_code < 100 || 200 <= c$sip$status_code )
			delete c$sip_state$pending[c$sip_state$current_response];

		if ( ! c$sip?$method || ( c$sip$method == "BYE" &&
		     c$sip$status_code >= 200 && c$sip$status_code < 300 ) )
			{
			flush_pending(c);
			delete c$sip;
			delete c$sip_state;
			}
		}
	}

hook finalize_sip(c: connection)
	{
	if ( c?$sip_state )
		{
		for ( r, info in c$sip_state$pending )
			{
			Log::write(SIP::LOG, info);
			}
		}
	}
