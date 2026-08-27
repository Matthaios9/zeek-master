


@load ./consts
@load base/protocols/conn/removal-hooks

module KRB;

export {
	redef enum Log::ID += { LOG };


	const tcp_ports = { 88/tcp } &redef;


	const udp_ports = { 88/udp } &redef;

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts:            time     &log;

		uid:           string   &log;

		id:            conn_id  &log;




		request_type:  string   &log &optional;

		client:        string   &log &optional;

		service:       string   &log &optional;


		success:       bool     &log &optional;

		error_code:    count    &optional;

		error_msg:     string   &log &optional;


		from:          time     &log &optional;

		till:          time     &log &optional;

		cipher:        string   &log &optional;


		forwardable:   bool     &log &optional;

		renewable:     bool     &log &optional;


		logged:        bool     &default=F;
	};


	option ignored_errors: set[string] = {





		"NEEDED_PREAUTH",


		"Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ",
	};



	global log_krb: event(rec: Info);


	global finalize_krb: Conn::RemovalHook;
}

redef record connection += {
	krb: Info &optional;
};

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_KRB, udp_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_KRB_TCP, tcp_ports);
	Log::create_stream(KRB::LOG, Log::Stream($columns=Info, $ev=log_krb, $path="kerberos", $policy=log_policy));
	}

function set_session(c: connection): bool
	{
	if ( ! c?$krb )
		{
		c$krb = Info($ts  = network_time(),
		             $uid = c$uid,
		             $id  = c$id);
		Conn::register_removal_hook(c, finalize_krb);
		}

	return c$krb$logged;
	}

function do_log(c: connection)
	{
	if ( c?$krb && ! c$krb$logged )
		{
		Log::write(KRB::LOG, c$krb);
		c$krb$logged = T;
		}
	}

event krb_error(c: connection, msg: Error_Msg) &priority=5
	{
	if ( set_session(c) )
		return;

	if ( msg?$error_text && msg$error_text in ignored_errors )
		{
		if ( c?$krb )
			delete c$krb;

		return;
		}

	if ( ! c$krb?$client && ( msg?$client_name || msg?$client_realm ) )
		c$krb$client = fmt("%s%s", msg?$client_name ? msg$client_name + "/" : "",
		                           msg?$client_realm ? msg$client_realm : "");

	if ( msg?$service_name )
		c$krb$service    = msg$service_name;

	c$krb$success    = F;
	c$krb$error_code = msg$error_code;

	if ( msg?$error_text )
		c$krb$error_msg = msg$error_text;
	else if ( msg$error_code in error_msg )
		c$krb$error_msg = error_msg[msg$error_code];
	}

event krb_error(c: connection, msg: Error_Msg) &priority=-5
	{
	do_log(c);
	}

event krb_as_request(c: connection, msg: KDC_Request) &priority=5
	{
	if ( set_session(c) )
		return;

	c$krb$request_type = "AS";

	c$krb$client       = fmt("%s/%s", msg?$client_name ? msg$client_name : "",
	                                  msg?$service_realm ? msg$service_realm : "");

	if ( msg?$service_name )
		c$krb$service      = msg$service_name;

	if ( msg?$from )
		c$krb$from = msg$from;
	if ( msg?$till )
		c$krb$till = msg$till;

	if ( msg?$kdc_options )
		{
		c$krb$forwardable = msg$kdc_options$forwardable;
		c$krb$renewable   = msg$kdc_options$renewable;
		}
	}

event krb_as_response(c: connection, msg: KDC_Response) &priority=5
	{
	if ( set_session(c) )
		return;

	if ( ! c$krb?$client && ( msg?$client_name || msg?$client_realm ) )
		{
		c$krb$client = fmt("%s/%s", msg?$client_name ? msg$client_name : "",
	                                msg?$client_realm ? msg$client_realm : "");
		}

	c$krb$service = msg$ticket$service_name;
	c$krb$cipher  = cipher_name[msg$ticket$cipher];
	c$krb$success = T;
	}

event krb_as_response(c: connection, msg: KDC_Response) &priority=-5
	{
	do_log(c);
	}

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options, in_kdc_padata: bool) &priority=5
	{
	if ( set_session(c) )
		return;


	if ( in_kdc_padata )
		return;

	c$krb$request_type = "AP";

	if ( ticket?$service_name )
		c$krb$service = ticket$service_name;
	if ( ticket?$cipher )
		c$krb$cipher = cipher_name[ticket$cipher];


	if ( ticket?$realm )
		c$krb$client = fmt("/%s", ticket$realm);
	}

event krb_ap_response(c: connection) &priority=5
	{
	if ( set_session(c) )
		return;



	c$krb$success = T;
	}

event krb_ap_response(c: connection) &priority=-5
	{
	do_log(c);
	}

event krb_tgs_request(c: connection, msg: KDC_Request) &priority=5
	{
	if ( set_session(c) )
		return;

	c$krb$request_type = "TGS";
	if ( msg?$service_name )
		c$krb$service = msg$service_name;
	if ( msg?$from )
		c$krb$from = msg$from;
	if ( msg?$till )
		c$krb$till = msg$till;

	if ( msg?$kdc_options )
		{
		c$krb$forwardable = msg$kdc_options$forwardable;
		c$krb$renewable   = msg$kdc_options$renewable;
		}
	}

event krb_tgs_response(c: connection, msg: KDC_Response) &priority=5
	{
	if ( set_session(c) )
		return;

	if ( ! c$krb?$client && ( msg?$client_name || msg?$client_realm ) )
		{
		c$krb$client = fmt("%s/%s", msg?$client_name ? msg$client_name : "",
	                                msg?$client_realm ? msg$client_realm : "");
		}

	c$krb$service = msg$ticket$service_name;
	c$krb$cipher  = cipher_name[msg$ticket$cipher];
	c$krb$success = T;
	}

event krb_tgs_response(c: connection, msg: KDC_Response) &priority=-5
	{
	do_log(c);
	}

hook finalize_krb(c: connection)
	{
	do_log(c);
	}
