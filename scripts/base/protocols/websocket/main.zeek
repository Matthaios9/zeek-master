





@load base/protocols/http

@load ./consts

module WebSocket;


redef HTTP::upgrade_analyzers += {
	["websocket"] = Analyzer::ANALYZER_WEBSOCKET,
};

export {
	redef enum Log::ID += { LOG };


	type Info: record {

		ts:                time    &log;

		uid:               string  &log;

		id:                conn_id &log;

		host:              string &log &optional;

		uri:               string &log &optional;

		user_agent:        string &log &optional;

		subprotocol:       string &log &optional;

		client_protocols:  vector of string &log &optional;

		server_extensions: vector of string &log &optional;

		client_extensions: vector of string &log &optional;

		client_key:        string &optional;

		server_accept:     string &optional;
	};



	global log_websocket: event(rec: Info);


	global log_policy: Log::PolicyHook;

















	global configure_analyzer: hook(c: connection, aid: count, config: AnalyzerConfig);
}

redef record connection += {
	websocket: Info &optional;
};

function set_websocket(c: connection)
	{
	c$websocket = Info(
		$ts=network_time(),
		$uid=c$uid,
		$id=c$id,
	);
	}

function expected_accept_for(key: string): string
	{
	return encode_base64(hexstr_to_bytestring(sha1_hash(key + HANDSHAKE_GUID)));
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( ! starts_with(name, "SEC-WEBSOCKET-") )
		return;

	if ( ! c?$websocket )
		set_websocket(c);

	local ws = c$websocket;

	if ( is_orig )
		{
		if ( name == "SEC-WEBSOCKET-PROTOCOL" )
			{
			if ( ! ws?$client_protocols )
				ws$client_protocols = vector();

			ws$client_protocols += split_string(value, / *, */);
			}

		else if ( name == "SEC-WEBSOCKET-EXTENSIONS" )
			{
			if ( ! ws?$client_extensions )
				ws$client_extensions = vector();

			ws$client_extensions += split_string(value, / *, */);
			}
		else if ( name == "SEC-WEBSOCKET-KEY" )
			{
			if ( ws?$client_key )
				Reporter::conn_weird("websocket_multiple_key_headers", c, "", "WebSocket");

			ws$client_key = value;
			}
		}
	else
		{
		if ( name == "SEC-WEBSOCKET-PROTOCOL" )
			{
			if ( ws?$subprotocol )
				Reporter::conn_weird("websocket_multiple_protocol_headers", c, "", "WebSocket");

			ws$subprotocol = value;
			}
		else if ( name == "SEC-WEBSOCKET-EXTENSIONS" )
			{
			if ( ! ws?$server_extensions )
				ws$server_extensions = vector();

			ws$server_extensions += split_string(value, / *, */);
			}
		else if ( name == "SEC-WEBSOCKET-ACCEPT" )
			{
			if ( ws?$server_accept )
				Reporter::conn_weird("websocket_multiple_accept_headers", c, "", "WebSocket");

			ws$server_accept = value;
			}
		}
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
	{







	if ( c?$websocket )
		delete c$websocket;
	}

event websocket_established(c: connection, aid: count) &priority=5
	{
	if ( ! c?$websocket )
		{

		Reporter::conn_weird("websocket_established_unexpected", c, "", "WebSocket");
		set_websocket(c);
		}

	local ws = c$websocket;

	if ( ! ws?$client_key )
		Reporter::conn_weird("websocket_missing_key_header", c, "", "WebSocket");

	if ( ! ws?$server_accept )
		Reporter::conn_weird("websocket_missing_accept_header", c, "", "WebSocket");


	if ( ws?$client_key && ws?$server_accept )
		{
		local expected_accept = expected_accept_for(ws$client_key);
		if ( ws$server_accept != expected_accept )
			Reporter::conn_weird("websocket_wrong_accept_header", c,
			                     fmt("expected=%s, found=%s", expected_accept, ws$server_accept),
			                     "WebSocket");
		}


	if ( c?$http )
		{
		if ( c$http?$host )
			ws$host = c$http$host;

		if ( c$http?$uri )
			ws$uri = c$http$uri;

		if ( c$http?$user_agent )
			ws$user_agent = c$http$user_agent;
		}
	}

event websocket_established(c: connection, aid: count) &priority=-5
	{
	local ws = c$websocket;

	local config = AnalyzerConfig();
	if ( ws?$subprotocol )
		config$subprotocol = ws$subprotocol;

	if ( ws?$server_extensions )
		config$server_extensions = ws$server_extensions;





	if ( hook WebSocket::configure_analyzer(c, aid, config) )
		WebSocket::__configure_analyzer(c, aid, config);
	else
		disable_analyzer(c$id, aid);

	ws$ts = network_time();
	Log::write(LOG, ws);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $ev=log_websocket, $path="websocket", $policy=log_policy));
	}
