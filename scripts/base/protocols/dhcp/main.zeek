





@load base/frameworks/cluster
@load ./consts

module DHCP;

export {
	redef enum Log::ID += { LOG };




	const server_ports = { 67/udp, 4011/udp } &redef;

	const client_ports = { 68/udp } &redef;

	global log_policy: Log::PolicyHook;


	type Info: record {


		ts:             time        &log;





		uids:           set[string] &log;








		client_addr:    addr        &log &optional;







		server_addr:    addr        &log &optional;



		client_port:    port             &optional;


		server_port:    port             &optional;


		mac:            string      &log &optional;


		host_name:      string      &log &optional;

		client_fqdn:    string      &log &optional;

		domain:         string      &log &optional;


		requested_addr: addr        &log &optional;

		assigned_addr:  addr        &log &optional;

		lease_time:     interval    &log &optional;




		client_message: string      &log &optional;


		server_message: string      &log &optional;


		msg_types:      vector of string &log &default=string_vec();



		duration:       interval    &log &default=0secs;


		client_chaddr:  string      &optional;
	};




	option DHCP::max_txid_watch_time = 30secs;


	option DHCP::max_uids_per_log_entry = 10;


	option DHCP::max_msg_types_per_log_entry = 50;





	global DHCP::aggregate_msgs: event(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options);





	global DHCP::log_info: Info;



	global log_dhcp: event(rec: Info);
}


redef record connection += {
	dhcp: Info &optional;
};

redef record Info += {
	last_message_ts: time &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(DHCP::LOG, Log::Stream($columns=Info, $ev=log_dhcp, $path="dhcp", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_DHCP, server_ports, client_ports);
	}

function join_data_expiration(t: table[count] of Info, idx: count): interval
	{
	local info = t[idx];

	local now = network_time();




	if ( (now - info$last_message_ts) > 5sec ||
	     (now - info$ts) > max_txid_watch_time ||
	     zeek_is_terminating() )
		{



		if ( ! info?$mac && info?$client_chaddr )
			info$mac = info$client_chaddr;

		Log::write(LOG, info);



		return 0secs;
		}
	else
		{
		return 5secs;
		}
	}




global join_data: table[count] of Info = table()
	&create_expire=10secs &expire_func=join_data_expiration;



@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )



event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=1000
	{
	if ( msg$xid !in join_data )
		{
		join_data[msg$xid] = Info($ts=ts,
		                          $uids=set(uid));
		}

	log_info = join_data[msg$xid];
	}

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
	{
	log_info$duration = ts - log_info$ts;

	if ( uid !in log_info$uids )
		add log_info$uids[uid];

	log_info$msg_types += DHCP::message_types[msg$m_type];




	local is_client = is_orig && (id$orig_h == 0.0.0.0 || id$orig_p == 68/udp || id$resp_p == 67/udp);



	if ( options?$message )
		{
		if ( is_client )
			log_info$client_message = options$message;
		else
			log_info$server_message = options$message;
		}



	log_info$last_message_ts = ts;

	if ( is_client )
		{




		if ( id$orig_h != 0.0.0.0 && id$orig_h != 255.255.255.255 )
			log_info$client_addr = id$orig_h;

		if ( options?$host_name )
			log_info$host_name = options$host_name;

		if ( options?$client_fqdn )
			log_info$client_fqdn = options$client_fqdn$domain_name;

		if ( options?$client_id &&
		     options$client_id$hwtype == 1 )
			log_info$mac = options$client_id$hwaddr;
		else
			log_info$client_chaddr = msg$chaddr;

		if ( options?$addr_request )
			log_info$requested_addr = options$addr_request;
		}
	else
		{


		if ( msg$yiaddr != 0.0.0.0 )
			{
			if ( is_orig )
				{



				log_info$server_addr = id$orig_h;
				log_info$server_port = id$orig_p;
				log_info$client_port = id$resp_p;
				}
			else
				{




				log_info$server_addr = id$resp_h;
				log_info$server_port = id$resp_p;
				log_info$client_port = id$orig_p;
				}
			}



		if ( msg$chaddr != "" && !log_info?$mac )
			log_info$mac = msg$chaddr;

		if ( msg$yiaddr != 0.0.0.0 )
			log_info$assigned_addr = msg$yiaddr;


		if ( ! log_info?$client_addr && log_info?$assigned_addr )
			log_info$client_addr = log_info$assigned_addr;

		if ( options?$domain_name )
			log_info$domain = options$domain_name;

		if ( options?$lease )
			log_info$lease_time = options$lease;
		}


	if ( |log_info$uids| >= max_uids_per_log_entry || |log_info$msg_types| >= max_msg_types_per_log_entry )
		{
		Log::write(LOG, log_info);
		delete join_data[msg$xid];
		}
	}
@endif




event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=-5
	{
	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		Cluster::publish(Cluster::manager_topic, DHCP::aggregate_msgs,
		                 network_time(), c$id, c$uid, is_orig, msg, options);
	else
		event DHCP::aggregate_msgs(network_time(), c$id, c$uid, is_orig, msg, options);
	}

event zeek_done() &priority=-5
	{

	for ( i in DHCP::join_data )
		join_data_expiration(DHCP::join_data, i);
	}
