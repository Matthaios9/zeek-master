

@load ./consts
@load base/protocols/conn/removal-hooks

module RDP;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;


	const rdp_ports = { 3389/tcp } &redef;


	const rdpeudp_ports = { 3389/udp } &redef;

	type Info: record {

		ts:                    time    &log;

		uid:                   string  &log;

		id:                    conn_id &log;



		cookie:                string  &log &optional;



		result:                string  &log &optional;

		security_protocol:     string &log &optional;

		client_channels:       vector of string &log &optional;


		keyboard_layout:       string  &log &optional;

		client_build:          string  &log &optional;

		client_name:           string  &log &optional;

		client_dig_product_id: string  &log &optional;

		desktop_width:         count   &log &optional;

		desktop_height:        count   &log &optional;


		requested_color_depth: string  &log &optional;




		cert_type:             string  &log &optional;


		cert_count:            count   &log &default=0;


		cert_permanent:        bool    &log &optional;

		encryption_level:      string  &log &optional;

		encryption_method:     string  &log &optional;
		};



	option disable_analyzer_after_detection = F;



	option rdp_check_interval = 10secs;



	global log_rdp: event(rec: Info);


	global finalize_rdp: Conn::RemovalHook;
}


redef record Info += {



	analyzer_id: count &optional;

	done:        bool  &default=F;
};

redef record connection += {
	rdp: Info &optional;
};


event zeek_init() &priority=5
	{
	Log::create_stream(RDP::LOG, Log::Stream($columns=RDP::Info, $ev=log_rdp, $path="rdp", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_RDP, rdp_ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_RDPEUDP, rdpeudp_ports);
	}

function write_log(c: connection)
	{
	local info = c$rdp;

	if ( info$done )
		return;


	info$done = T;



	if ( info?$cookie || info?$keyboard_layout || info?$result )
		Log::write(RDP::LOG, info);
	}

event check_record(c: connection)
	{

	if ( c$rdp$done )
		return;



	local diff = network_time() - c$rdp$ts;
	if ( diff > rdp_check_interval )
		{
		write_log(c);


		if ( disable_analyzer_after_detection &&
		     connection_exists(c$id) &&
		     c$rdp?$analyzer_id )
			{
			disable_analyzer(c$id, c$rdp$analyzer_id);
			}

		return;
		}
	else
		{



		schedule rdp_check_interval { check_record(c) };
		}
	}

function set_session(c: connection)
	{
	if ( ! c?$rdp )
		{
		c$rdp = Info($ts=network_time(),$id=c$id,$uid=c$uid);
		Conn::register_removal_hook(c, finalize_rdp);


		schedule rdp_check_interval { check_record(c) };
		}
	}

event rdp_connect_request(c: connection, cookie: string) &priority=5
	{
	set_session(c);

	c$rdp$cookie = cookie;
	}

event rdp_negotiation_response(c: connection, security_protocol: count) &priority=5
	{
	set_session(c);

	c$rdp$security_protocol = security_protocols[security_protocol];
	}

event rdp_negotiation_failure(c: connection, failure_code: count) &priority=5
	{
	set_session(c);

	c$rdp$result = failure_codes[failure_code];
	}

event rdp_client_core_data(c: connection, data: RDP::ClientCoreData) &priority=5
	{
	set_session(c);

	if (data$keyboard_layout in RDP::languages)
		{
		c$rdp$keyboard_layout = RDP::languages[data$keyboard_layout];
		}
	else
		{
		if (data$keyboard_layout & 0xffff in RDP::languages)
			c$rdp$keyboard_layout = fmt("%s (Best Guess for %d)", RDP::languages[data$keyboard_layout & 0xffff], data$keyboard_layout);
		else
			c$rdp$keyboard_layout = fmt("keyboard-%d", data$keyboard_layout);
		}

	c$rdp$client_build          = RDP::builds[data$client_build];
	c$rdp$client_name           = data$client_name;
	c$rdp$client_dig_product_id = data$dig_product_id;
	c$rdp$desktop_width         = data$desktop_width;
	c$rdp$desktop_height        = data$desktop_height;

	if ( data?$ec_flags && data$ec_flags$want_32bpp_session )
		c$rdp$requested_color_depth = "32bit";
	else
		c$rdp$requested_color_depth = RDP::high_color_depths[data$high_color_depth];
	}

event rdp_client_network_data(c: connection, channels: ClientChannelList)
	{
	set_session(c);

	if ( ! c$rdp?$client_channels )
		c$rdp$client_channels = vector();

	for ( i in channels )

		c$rdp$client_channels[i] = gsub(channels[i]$name, /\x00+$/, "");

	if ( |channels| > 31 )
		Reporter::conn_weird("RDP_channels_requested_exceeds_max", c, fmt("%s", |channels|));
	}

event rdp_gcc_server_create_response(c: connection, result: count) &priority=5
	{
	set_session(c);

	c$rdp$result = RDP::results[result];
	}

event rdp_server_security(c: connection, encryption_method: count, encryption_level: count) &priority=5
	{
	set_session(c);

	c$rdp$encryption_method = RDP::encryption_methods[encryption_method];
	c$rdp$encryption_level = RDP::encryption_levels[encryption_level];
	}

event rdp_server_certificate(c: connection, cert_type: count, permanently_issued: bool) &priority=5
	{
	set_session(c);

	c$rdp$cert_type = RDP::cert_types[cert_type];



	if ( c$rdp$cert_type == "RSA" )
		++c$rdp$cert_count;

	c$rdp$cert_permanent = permanently_issued;
	}

event rdp_begin_encryption(c: connection, security_protocol: count) &priority=5
	{
	set_session(c);

	if ( ! c$rdp?$result )
		{
		c$rdp$result = "encrypted";
		}

	c$rdp$security_protocol = security_protocols[security_protocol];
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( c?$rdp && f$source == "RDP" )
		{

		++c$rdp$cert_count;
		}
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=5
	{
	if ( atype == Analyzer::ANALYZER_RDP )
		{
		set_session(info$c);
		info$c$rdp$analyzer_id = info$aid;
		}
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=5
	{

	if ( atype == Analyzer::ANALYZER_RDP && info$c?$rdp )
		write_log(info$c);
	}

hook finalize_rdp(c: connection)
	{

	if ( c?$rdp )
		{
		write_log(c);
		}
	}
