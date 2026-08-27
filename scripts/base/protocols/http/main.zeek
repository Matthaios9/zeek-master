



@load base/utils/numbers
@load base/utils/files
@load base/frameworks/tunnels
@load base/protocols/conn/removal-hooks

module HTTP;

export {
	redef enum Log::ID += { LOG };


	const ports = {
		80/tcp, 81/tcp, 631/tcp, 1080/tcp, 3128/tcp,
		8000/tcp, 8080/tcp, 8888/tcp,
	} &redef;

	global log_policy: Log::PolicyHook;


	type Tags: enum {

		EMPTY
	};



	option default_capture_password = F;


	type Info: record {

		ts:                      time      &log;

		uid:                     string    &log;

		id:                      conn_id   &log;


		trans_depth:             count     &log;

		method:                  string    &log &optional;

		host:                    string    &log &optional;

		uri:                     string    &log &optional;



		referrer:                string    &log &optional;




		version:		string	   &log &optional;

		user_agent:              string    &log &optional;

		origin:                  string    &log &optional;


		request_body_len:        count     &log &default=0;


		response_body_len:       count     &log &default=0;

		status_code:             count     &log &optional;

		status_msg:              string    &log &optional;

		info_code:               count     &log &optional;

		info_msg:                string    &log &optional;


		tags:                    set[Tags] &log;


		username:                string    &log &optional;

		password:                string    &log &optional;


		capture_password:        bool      &default=default_capture_password;


		proxied:                 set[string] &log &optional;



		range_request:           bool      &default=F;
	};



	type State: record {

		pending:          table[count] of Info;

		current_request:  count                &default=0;

		current_response: count                &default=0;



		trans_depth:      count                &default=0;
	};


	option proxy_headers: set[string] = {
		"FORWARDED",
		"X-FORWARDED-FOR",
		"X-FORWARDED-FROM",
		"CLIENT-IP",
		"VIA",
		"XROXY-CONNECTION",
		"PROXY-CONNECTION",
	};




	option http_methods: set[string] = {
		"GET", "POST", "HEAD", "OPTIONS",
		"PUT", "DELETE", "TRACE", "CONNECT",

		"PROPFIND", "PROPPATCH", "MKCOL",
		"COPY", "MOVE", "LOCK", "UNLOCK",
		"POLL", "REPORT", "SUBSCRIBE", "BMOVE",
		"SEARCH",

		"QUERY",
	};



	global log_http: event(rec: Info);


	global finalize_http: Conn::RemovalHook;





	option max_pending_requests = 100;







	const default_max_field_string_bytes = 0 &redef;
}


redef record connection += {
	http:        Info  &optional;
	http_state:  State &optional;
};



event zeek_init() &priority=5
	{
	Log::create_stream(HTTP::LOG, Log::Stream($columns=Info, $ev=log_http, $path="http", $policy=log_policy,
	                                          $max_field_string_bytes=HTTP::default_max_field_string_bytes));
	Analyzer::register_for_ports(Analyzer::ANALYZER_HTTP, ports);
	}

function code_in_range(c: count, min: count, max: count) : bool
	{
	return c >= min && c <= max;
	}

function new_http_session(c: connection): Info
	{
	local tmp: Info;
	tmp$ts=network_time();
	tmp$uid=c$uid;
	tmp$id=c$id;
	tmp$trans_depth = ++c$http_state$trans_depth;
	return tmp;
	}

function set_state(c: connection, is_orig: bool)
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		Conn::register_removal_hook(c, finalize_http);
		}


	if ( is_orig )
		{
		if ( c$http_state$current_request !in c$http_state$pending )
			c$http_state$pending[c$http_state$current_request] = new_http_session(c);

		c$http = c$http_state$pending[c$http_state$current_request];
		}
	else
		{
		if ( c$http_state$current_response !in c$http_state$pending )
			c$http_state$pending[c$http_state$current_response] = new_http_session(c);

		c$http = c$http_state$pending[c$http_state$current_response];
		}
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=5
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		Conn::register_removal_hook(c, finalize_http);
		}





	if ( c$http_state$current_request < c$http_state$current_response )
		{
		Reporter::conn_weird("HTTP_response_before_request", c);
		c$http_state$current_request = c$http_state$current_response;
		}







	if ( max_pending_requests > 0 && |c$http_state$pending| > max_pending_requests )
		{
		Reporter::conn_weird("HTTP_excessive_pipelining", c);

		if ( c$http_state$current_response == 0 )
			++c$http_state$current_response;

		while ( c$http_state$current_response < c$http_state$current_request )
			{
			local cr = c$http_state$current_response;
			if ( cr in c$http_state$pending )
				{
				Log::write(HTTP::LOG, c$http_state$pending[cr]);
				delete c$http_state$pending[cr];
				}
			else
				{


				}

			++c$http_state$current_response;
			}
		}

	++c$http_state$current_request;
	set_state(c, T);

	c$http$method = method;
	c$http$uri = unescaped_URI;

	if ( method !in http_methods )
		Reporter::conn_weird("unknown_HTTP_method", c, method);
	}

event http_reply(c: connection, version: string, code: count, reason: string) &priority=5
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		Conn::register_removal_hook(c, finalize_http);
		}



	if ( c$http_state$current_response !in c$http_state$pending ||
	     (c$http_state$pending[c$http_state$current_response]?$status_code &&
	       ! code_in_range(c$http_state$pending[c$http_state$current_response]$status_code, 100, 199)) )
		{
		++c$http_state$current_response;
		}
	set_state(c, F);

	c$http$status_code = code;
	c$http$status_msg = reason;
	c$http$version = version;

	if ( code_in_range(code, 100, 199) )
		{
		c$http$info_code = code;
		c$http$info_msg = reason;
		}

	if ( c$http?$method && c$http$method == "CONNECT" && code == 200 )
		{




		local tid = copy(c$id);
		tid$orig_p = 0/tcp;
		Tunnel::register(Tunnel::EncapsulatingConn($cid=tid, $tunnel_type=Tunnel::HTTP));
		}
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
	{
	set_state(c, is_orig);

	if ( is_orig )
		{
		if ( name == "REFERER" )
			c$http$referrer = value;

		else if ( name == "HOST" )


			c$http$host = value;

		else if ( name == "RANGE" )
			c$http$range_request = T;

		else if ( name == "ORIGIN" )
			c$http$origin = value;

		else if ( name == "USER-AGENT" )
			c$http$user_agent = value;

		else if ( name in proxy_headers )
				{
				if ( ! c$http?$proxied )
					c$http$proxied = set();
				add c$http$proxied[fmt("%s -> %s", name, value)];
				}

		else if ( name == "AUTHORIZATION" || name == "PROXY-AUTHORIZATION" )
			{
			if ( /^[bB][aA][sS][iI][cC] / in value )
				{
				local userpass = decode_base64_conn(c$id, sub(value, /[bB][aA][sS][iI][cC][[:blank:]]+/, ""));
				local up = split_string1(userpass, /:/);
				if ( |up| == 2 )
					{
					c$http$username = up[0];
					if ( c$http$capture_password )
						c$http$password = up[1];
					}
				else
					{
					c$http$username = fmt("<problem-decoding> (%s)", value);
					if ( c$http$capture_password )
						c$http$password = userpass;
					}
				}
			}
		}
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = 5
	{
	set_state(c, is_orig);

	if ( is_orig )
		c$http$request_body_len = stat$body_length;
	else
		c$http$response_body_len = stat$body_length;
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = -5
	{

	if ( ! is_orig )
		{


		if ( ! (c$http?$status_code && code_in_range(c$http$status_code, 100, 199)) )
			{
			Log::write(HTTP::LOG, c$http);
			delete c$http_state$pending[c$http_state$current_response];
			}
		}
	}

hook finalize_http(c: connection)
	{

	if ( c?$http_state )
		{
		for ( r, info in c$http_state$pending )
			{

			if ( r == 0 ) next;
			Log::write(HTTP::LOG, info);
			}
		}
	}
