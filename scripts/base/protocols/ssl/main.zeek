


@load base/frameworks/notice/weird
@load ./consts
@load base/protocols/conn/removal-hooks

module SSL;

export {
	redef enum Log::ID += { LOG };


	const ssl_ports = {
		443/tcp, 465/tcp, 563/tcp, 585/tcp, 614/tcp, 636/tcp,
		989/tcp, 990/tcp, 992/tcp, 993/tcp, 995/tcp, 5223/tcp
	} &redef;




	const dtls_ports = { 443/udp } &redef;

	global log_policy: Log::PolicyHook;


	type Info: record {

		ts:               time             &log;

		uid:              string           &log;

		id:               conn_id          &log;

		version_num:      count            &optional;

		version:          string           &log &optional;

		cipher:           string           &log &optional;

		curve:            string           &log &optional;


		server_name:      string           &log &optional;


		session_id:       string           &optional;


		resumed:          bool             &log &default=F;




		client_ticket_empty_session_seen: bool &default=F;



		client_key_exchange_seen: bool     &default=F;



		client_psk_seen: bool     &default=F;


		last_alert:       string           &log &optional;


		next_protocol:    string           &log &optional;




		analyzer_id:      count            &optional;



		established:      bool             &log &default=F;


		logged:           bool             &default=F;


		hrr_seen:         bool             &default=F;








































		ssl_history:          string &log &default="";
	};



	const root_certs: table[string] of string &redef;



	type CTInfo: record {

		description:           string;

		operator:              string;

		key:                   string;

		maximum_merge_delay:   count;

		url:                   string;
	};




	option ct_logs: table[string] of CTInfo = {};




	option disable_analyzer_after_detection = T;



	option max_ssl_history_length = 100;



	global delay_log: function(info: Info, token: string);



	global undelay_log: function(info: Info, token: string);



	global log_ssl: event(rec: Info);



	global ssl_finishing: hook(c: connection);






	global finalize_ssl: Conn::RemovalHook;
}

redef record connection += {
	ssl: Info &optional;
};

redef record Info += {



	delay_tokens: set[string] &optional;
};


event zeek_init() &priority=6
	{
	Log::create_stream(SSL::LOG, Log::Stream($columns=Info, $ev=log_ssl, $path="ssl", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_SSL, ssl_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DTLS, dtls_ports);
	}

function set_session(c: connection)
	{
	if ( ! c?$ssl )
		{
		c$ssl = Info($ts=network_time(), $uid=c$uid, $id=c$id);
		Conn::register_removal_hook(c, finalize_ssl);
		}
	}

function add_to_history(c: connection, is_client: bool, char: string)
	{
	if ( |c$ssl$ssl_history| == max_ssl_history_length )
		return;

	if ( is_client )
		c$ssl$ssl_history = c$ssl$ssl_history+to_upper(char);
	else
		c$ssl$ssl_history = c$ssl$ssl_history+to_lower(char);

	if ( |c$ssl$ssl_history| == max_ssl_history_length )
		Reporter::conn_weird("SSL_max_ssl_history_length_reached", c);
	}

function delay_log(info: Info, token: string)
	{
	if ( ! info?$delay_tokens )
		info$delay_tokens = set();
	add info$delay_tokens[token];
	}

function undelay_log(info: Info, token: string)
	{
	if ( info?$delay_tokens && token in info$delay_tokens )
		delete info$delay_tokens[token];
	}

function log_record(info: Info)
	{
	if ( info$logged )
		return;

	if ( ! info?$delay_tokens || |info$delay_tokens| == 0 )
		{
		Log::write(SSL::LOG, info);
		info$logged = T;
		}
	else
		{
		when [info] ( |info$delay_tokens| == 0 )
			{
			log_record(info);
			}
		timeout 15secs
			{

			delete info$delay_tokens;
			log_record(info);
			}
		}
	}



function finish(c: connection, remove_analyzer: bool)
	{
	log_record(c$ssl);
	if ( remove_analyzer && disable_analyzer_after_detection && c?$ssl && c$ssl?$analyzer_id )
		if ( disable_analyzer(c$id, c$ssl$analyzer_id) )
			delete c$ssl$analyzer_id;
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=5
	{
	set_session(c);


	if ( |session_id| > 0 && session_id != /^\x00{32}$/ )
		{
		c$ssl$session_id = bytestring_to_hexstr(session_id);
		c$ssl$client_ticket_empty_session_seen = F;
		}





	if ( record_version == 0 )
		add_to_history(c, T, "c");
	}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=5
	{
	set_session(c);


	if ( ! c$ssl?$version_num )
		{
		c$ssl$version_num = version;
		c$ssl$version = version_strings[version];
		}
	c$ssl$cipher = cipher_desc[cipher];


	if ( server_random == "\xCF\x21\xAD\x74\xE5\x9A\x61\x11\xBE\x1D\x8C\x02\x1E\x65\xB8\x91\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E\x07\x9E\x09\xE2\xC8\xA8\x33\x9C" )
		c$ssl$hrr_seen = T;

	if ( c$ssl?$session_id && c$ssl$session_id == bytestring_to_hexstr(session_id) && c$ssl$version_num/0xFF != 0x7F && c$ssl$version_num != TLSv13 )
		c$ssl$resumed = T;



	if ( version == 2 )
		add_to_history(c, F, "s");
	}

event ssl_extension_supported_versions(c: connection, is_client: bool, versions: index_vec)
	{
	if ( is_client || |versions| != 1 )
		return;

	set_session(c);

	c$ssl$version_num = versions[0];
	c$ssl$version = version_strings[versions[0]];
	}

event ssl_ecdh_server_params(c: connection, curve: count, point: string) &priority=5
	{
	set_session(c);

	c$ssl$curve = ec_curves[curve];
	}

event ssl_extension_key_share(c: connection, is_client: bool, curves: index_vec)
	{
	if ( is_client || |curves| != 1 )
		return;

	set_session(c);
	c$ssl$curve = ec_curves[curves[0]];
	}

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec) &priority=5
	{
	set_session(c);

	if ( is_client && |names| > 0 )
		{
		c$ssl$server_name = names[0];
		if ( |names| > 1 )
			Reporter::conn_weird("SSL_many_server_names", c, cat(names));
		}
	}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, protocols: string_vec)
	{
	set_session(c);

	if ( is_client )
		return;

	if ( |protocols| > 0 )
		c$ssl$next_protocol = protocols[0];
	}

event ssl_connection_flipped(c: connection)
	{
	set_session(c);

	c$ssl$ssl_history += "^";
	}

event ssl_handshake_message(c: connection, is_client: bool, msg_type: count, length: count) &priority=5
	{
	set_session(c);

	if ( is_client && msg_type == SSL::CLIENT_KEY_EXCHANGE )
		c$ssl$client_key_exchange_seen = T;

	switch ( msg_type )
		{
		case SSL::HELLO_REQUEST:
			add_to_history(c, is_client, "h");
			break;
		case SSL::CLIENT_HELLO:
			add_to_history(c, is_client, "c");
			break;
		case SSL::SERVER_HELLO:
			if ( c$ssl$hrr_seen )
				{

				add_to_history(c, is_client, "j");
				c$ssl$hrr_seen = F;
				}
			else
				add_to_history(c, is_client, "s");
			break;
		case SSL::HELLO_VERIFY_REQUEST:
			add_to_history(c, is_client, "v");
			break;
		case SSL::SESSION_TICKET:
			add_to_history(c, is_client, "t");
			break;

		case 5:
			add_to_history(c, is_client, "e");
			break;
		case SSL::HELLO_RETRY_REQUEST:
			add_to_history(c, is_client, "j");
			break;
		case SSL::ENCRYPTED_EXTENSIONS:
			add_to_history(c, is_client, "o");
			break;
		case SSL::CERTIFICATE:
			add_to_history(c, is_client, "x");
			break;
		case SSL::SERVER_KEY_EXCHANGE:
			add_to_history(c, is_client, "k");
			break;
		case SSL::CERTIFICATE_REQUEST:
			add_to_history(c, is_client, "r");
			break;
		case SSL::SERVER_HELLO_DONE:
			add_to_history(c, is_client, "n");
			break;
		case SSL::CERTIFICATE_VERIFY:
			add_to_history(c, is_client, "y");
			break;
		case SSL::CLIENT_KEY_EXCHANGE:
			add_to_history(c, is_client, "g");
			break;
		case SSL::FINISHED:
			add_to_history(c, is_client, "f");
			break;
		case SSL::CERTIFICATE_URL:
			add_to_history(c, is_client, "w");
			break;
		case SSL::CERTIFICATE_STATUS:
			add_to_history(c, is_client, "u");
			break;
		case SSL::SUPPLEMENTAL_DATA:
			add_to_history(c, is_client, "a");
			break;
		case SSL::KEY_UPDATE:
			add_to_history(c, is_client, "p");
			break;

		case 254:
			add_to_history(c, is_client, "m");
			break;
		default:
			add_to_history(c, is_client, "z");
			break;
		}
	}



event ssl_extension(c: connection, is_client: bool, code: count, val: string) &priority=5
	{
	set_session(c);

	if ( is_client && code == SSL_EXTENSION_SESSIONTICKET_TLS && |val| > 0 )


		c$ssl$client_ticket_empty_session_seen = T;
	else if ( is_client && code == SSL_EXTENSION_PRE_SHARED_KEY )

		c$ssl$client_psk_seen = T;
	else if ( ! is_client && code == SSL_EXTENSION_PRE_SHARED_KEY && c$ssl$client_psk_seen )

		c$ssl$resumed = T;
	}

event ssl_change_cipher_spec(c: connection, is_client: bool) &priority=5
	{
	set_session(c);
	add_to_history(c, is_client, "i");

	if ( is_client && c$ssl$client_ticket_empty_session_seen && ! c$ssl$client_key_exchange_seen )
		c$ssl$resumed = T;
	}

event ssl_alert(c: connection, is_client: bool, level: count, desc: count) &priority=5
	{
	set_session(c);
	add_to_history(c, is_client, "l");

	c$ssl$last_alert = alert_descriptions[desc];
	}

event ssl_heartbeat(c: connection, is_client: bool, length: count, heartbeat_type: count, payload_length: count, payload: string)
	{
	set_session(c);
	add_to_history(c, is_client, "b");
	}

event ssl_established(c: connection) &priority=7
	{
	c$ssl$established = T;
	}

event ssl_established(c: connection) &priority=20
	{
	set_session(c);
	hook ssl_finishing(c);
	}

event ssl_established(c: connection) &priority=-5
	{
	finish(c, T);
	}

hook finalize_ssl(c: connection)
	{
	if ( ! c?$ssl )
		return;

	if ( ! c$ssl$logged )
		hook ssl_finishing(c);


	finish(c, F);
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=5
	{
	if ( atype == Analyzer::ANALYZER_SSL || atype == Analyzer::ANALYZER_DTLS )
		{
		set_session(info$c);
		info$c$ssl$analyzer_id = info$aid;
		}
	}

event ssl_plaintext_data(c: connection, is_client: bool, record_version: count, content_type: count, length: count) &priority=5
	{
	set_session(c);

	if ( ! c$ssl?$version || c$ssl$established || content_type != APPLICATION_DATA )
		return;

	Reporter::conn_weird("ssl_early_application_data", c);
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=5
	{
	if ( atype == Analyzer::ANALYZER_SSL || atype == Analyzer::ANALYZER_DTLS )
		if ( info$c?$ssl )
			{

			if ( ! info$c$ssl$logged )
				hook ssl_finishing(info$c);
			delete info$c$ssl$analyzer_id;
			finish(info$c, F);
			}
	}
