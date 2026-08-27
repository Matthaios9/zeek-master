module NTP;

export {
	redef enum Log::ID += { LOG, CONTROL_LOG, PRIVATE_LOG };


	const ports = { 123/udp } &redef;

	global log_policy: Log::PolicyHook;
	global log_policy_control: Log::PolicyHook;
	global log_policy_private: Log::PolicyHook;

	type Info: record {

		ts:         time	&log;

		uid:        string  &log;

		id:         conn_id &log;

		version:    count &log;

		mode:       count &log;

		stratum:    count &log;

		poll:       interval &log;

		precision:  interval &log;

		root_delay: interval &log;

		root_disp:  interval &log;







		ref_id:     string &log;

		ref_time:   time &log;

		org_time:   time &log;

		rec_time:   time &log;

		xmt_time:   time &log;

		num_exts:   count &default=0 &log;
	};



	type ControlInfo: record {

		ts:         time    &log;

		uid:        string  &log;

		id:         conn_id &log;

		version:    count   &log;

		mode:       count   &log;

		op_code:    count   &log;

		sequence:   count   &log;

		status:     count   &log;

		association_id: count &log;

		resp_bit:    bool    &log;

		err_bit:     bool    &log;

		more_bit:    bool    &log;

		data:        string  &log &optional;

		key_id:      count   &log &optional;

		crypto_checksum: string &log &optional;
	};



	type PrivateInfo: record {

		ts:         time    &log;

		uid:        string  &log;

		id:         conn_id &log;

		version:    count   &log;

		mode:       count   &log;

		req_code:   count   &log;

		sequence:   count   &log;

		implementation: count &log;

		auth_bit:    bool    &log;

		err:        count   &log;

		data:       string  &log &optional;
	};



	global log_ntp: event(rec: Info);


	global log_ntp_control: event(rec: ControlInfo);


	global log_ntp_private: event(rec: PrivateInfo);
}

redef record connection += {
	ntp:         Info        &optional;
	ntp_control: ControlInfo &optional;
	ntp_private: PrivateInfo &optional;
};

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);
	Log::create_stream(NTP::LOG, Log::Stream($columns = Info, $ev = log_ntp,
	                    $path="ntp", $policy=log_policy));
	Log::create_stream(NTP::CONTROL_LOG, Log::Stream($columns = ControlInfo,
	                    $ev = log_ntp_control, $path="ntp_control",
	                    $policy=log_policy_control));
	Log::create_stream(NTP::PRIVATE_LOG, Log::Stream($columns = PrivateInfo,
	                    $ev = log_ntp_private, $path="ntp_private",
	                    $policy=log_policy_private));
	}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=5
	{

	if ( msg?$std_msg )
		{
		local info: Info;
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;
		info$version = msg$version;
		info$mode = msg$mode;
		info$stratum = msg$std_msg$stratum;
		info$poll = msg$std_msg$poll;
		info$precision = msg$std_msg$precision;
		info$root_delay = msg$std_msg$root_delay;
		info$root_disp = msg$std_msg$root_disp;

		if ( msg$std_msg?$kiss_code )
			info$ref_id = msg$std_msg$kiss_code;
		else if ( msg$std_msg?$ref_id )
			info$ref_id = msg$std_msg$ref_id;
		else if ( msg$std_msg?$ref_addr )
			info$ref_id= cat(msg$std_msg$ref_addr);

		info$ref_time = msg$std_msg$ref_time;
		info$org_time = msg$std_msg$org_time;
		info$rec_time = msg$std_msg$rec_time;
		info$xmt_time = msg$std_msg$xmt_time;

		info$num_exts = msg$std_msg$num_exts;

		c$ntp = info;
		}


	if ( msg?$control_msg )
		{
		local ctrl: ControlInfo;
		ctrl$ts  = network_time();
		ctrl$uid = c$uid;
		ctrl$id  = c$id;
		ctrl$version = msg$version;
		ctrl$mode = msg$mode;
		ctrl$op_code = msg$control_msg$op_code;
		ctrl$sequence = msg$control_msg$sequence;
		ctrl$status = msg$control_msg$status;
		ctrl$association_id = msg$control_msg$association_id;
		ctrl$resp_bit = msg$control_msg$resp_bit;
		ctrl$err_bit = msg$control_msg$err_bit;
		ctrl$more_bit = msg$control_msg$more_bit;
		if ( msg$control_msg?$data )
			ctrl$data = msg$control_msg$data;
		if ( msg$control_msg?$key_id )
			ctrl$key_id = msg$control_msg$key_id;
		if ( msg$control_msg?$crypto_checksum )
			ctrl$crypto_checksum = msg$control_msg$crypto_checksum;

		c$ntp_control = ctrl;
		}


	if ( msg?$mode7_msg )
		{
		local priv: PrivateInfo;
		priv$ts  = network_time();
		priv$uid = c$uid;
		priv$id  = c$id;
		priv$version = msg$version;
		priv$mode = msg$mode;
		priv$req_code = msg$mode7_msg$req_code;
		priv$sequence = msg$mode7_msg$sequence;
		priv$implementation = msg$mode7_msg$implementation;
		priv$auth_bit = msg$mode7_msg$auth_bit;
		priv$err = msg$mode7_msg$err;
		if ( msg$mode7_msg?$data )
			priv$data = msg$mode7_msg$data;

		c$ntp_private = priv;
		}
	}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=-5
	{
	if ( c?$ntp )
		Log::write(NTP::LOG, c$ntp);

	if ( c?$ntp_control )
		Log::write(NTP::CONTROL_LOG, c$ntp_control);

	if ( c?$ntp_private )
		Log::write(NTP::PRIVATE_LOG, c$ntp_private);
	}
