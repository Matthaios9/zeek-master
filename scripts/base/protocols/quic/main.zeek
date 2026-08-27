

@load base/frameworks/notice/weird
@load base/protocols/conn/removal-hooks

@load ./consts

module QUIC;

export {
	redef enum Log::ID += { LOG };


	const quic_ports = {
		443/udp,
	} &redef;











	const doq_ports = {
		853/udp,
		784/udp,
	} &redef;

	type Info: record {

		ts:          time    &log;

		uid:         string  &log;

		id:          conn_id &log;




		version:     string  &log;




		client_initial_dcid: string  &log &optional;


		client_scid:         string  &log &optional;




		server_scid:         string  &log &optional;



		server_name: string  &log &optional;



		client_protocol: string &log &optional;



















		history: string &log &default="";


		history_state: vector of string;


		logged: bool &default=F;
	};

	global log_quic: event(rec: Info);

	global log_policy: Log::PolicyHook;

	global finalize_quic: Conn::RemovalHook;


	option max_history_length = 100;



	const max_discarded_packet_events: int = 100 &redef;
}

redef record connection += {


	quic: Info &optional;
};



function add_to_history(c: connection, is_orig: bool, what: string)
	{
	if ( |c$quic$history_state| == max_history_length )
		return;

	c$quic$history_state += is_orig ? to_upper(what[0]) : to_lower(what[0]);

	if ( |c$quic$history_state| == max_history_length )
		Reporter::conn_weird("QUIC_max_history_length_reached", c);
	}

function log_record(quic: Info)
	{
	quic$history = join_string_vec(quic$history_state, "");
	Log::write(LOG, quic);
	quic$logged = T;
	}

function set_session(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	if ( ! c?$quic )
		{
		c$quic = Info(
			$ts=network_time(),
			$uid=c$uid,
			$id=c$id,
			$version=version_strings[version],
		);

		Conn::register_removal_hook(c, finalize_quic);
		}

	if ( is_orig && |dcid| > 0 && ! c$quic?$client_initial_dcid )
		c$quic$client_initial_dcid = bytestring_to_hexstr(dcid);

	if ( is_orig )
		c$quic$client_scid = bytestring_to_hexstr(scid);
	else
		c$quic$server_scid = bytestring_to_hexstr(scid);
	}

event QUIC::initial_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	set_session(c, is_orig, version, dcid, scid);
	add_to_history(c, is_orig, "INIT");
	}

event QUIC::handshake_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	set_session(c, is_orig, version, dcid, scid);
	add_to_history(c, is_orig, "HANDSHAKE");
	}

event QUIC::zero_rtt_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	set_session(c, is_orig, version, dcid, scid);
	add_to_history(c, is_orig, "ZeroRTT");
	}


event QUIC::retry_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string, retry_token: string, integrity_tag: string)
	{
	if ( ! c?$quic )
		set_session(c, is_orig, version, dcid, scid);

	add_to_history(c, is_orig, "RETRY");

	log_record(c$quic);

	delete c$quic;
	}

event QUIC::short_header_packet_threshold_crossed(c: connection, is_orig: bool, threshold: count)
	{
	if ( ! c?$quic )
		{


		Reporter::conn_weird("QUIC_spurious_short_header_packet_threshold_crossed",
		                     c, cat(threshold));
		return;
		}

	add_to_history(c, is_orig, "Oshort_header");
	}

event QUIC::discarded_packet(c: connection, is_orig: bool, total_decrypted: count)
	{
	if ( ! c?$quic )
		{

		Reporter::conn_weird("QUIC_spurious_discarded_packet", c);
		return;
		}

	add_to_history(c, is_orig, "Xdiscarded");
	}


event QUIC::unhandled_version(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	if ( ! c?$quic )
		set_session(c, is_orig, version, dcid, scid);

	add_to_history(c, is_orig, "UNHANDLED_VERSION");

	log_record(c$quic);

	delete c$quic;
	}



event QUIC::connection_close_frame(c: connection, is_orig: bool, version: count, dcid: string, scid: string, error_code: count, reason_phrase: string)
	{
	if ( ! c?$quic )
		return;

	add_to_history(c, is_orig, "CONNECTION_CLOSE");

	log_record(c$quic);

	delete c$quic;
	}

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec) &priority=5
	{
	if ( is_client && c?$quic && |names| > 0 )
		c$quic$server_name = names[0];
	}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, protocols: string_vec)
	{
	if ( c?$quic && is_client )
		{
		c$quic$client_protocol = protocols[0];
		if ( |protocols| > 1 )



			Reporter::conn_weird("QUIC_many_protocols", c, cat(protocols));
		}
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
	{
	if ( ! c?$quic )
		return;

	add_to_history(c, T, "SSL");
	}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=-5
	{
	if ( ! c?$quic )
		return;

	add_to_history(c, F, "SSL");
	}

hook finalize_quic(c: connection)
	{
	if ( ! c?$quic || c$quic$logged )
		return;

	log_record(c$quic);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $ev=log_quic, $path="quic", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_QUIC, quic_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_QUIC, set(), doq_ports);
	}
