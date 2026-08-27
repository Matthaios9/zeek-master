

@load ./consts
@load base/utils/addrs
@load base/protocols/conn/removal-hooks

module RADIUS;

export {
	redef enum Log::ID += { LOG };


	const ports = { 1812/udp } &redef;

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts           : time     &log;

		uid          : string   &log;

		id           : conn_id  &log;

		username     : string   &log &optional;

		mac          : string   &log &optional;




		framed_addr  : addr     &log &optional;



		tunnel_client: string   &log &optional;

		connect_info : string   &log &optional;


		reply_msg    : string   &log &optional;

		result       : string   &log &optional;




		ttl          : interval &log &optional;


		logged       : bool     &default=F;
	};



	global log_radius: event(rec: Info);


	global finalize_radius: Conn::RemovalHook;
}

redef record connection += {
	radius: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(RADIUS::LOG, Log::Stream($columns=Info, $ev=log_radius, $path="radius", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_RADIUS, ports);
	}

event radius_message(c: connection, result: RADIUS::Message) &priority=5
	{
	if ( ! c?$radius )
		{
		c$radius = Info($ts  = network_time(),
		                $uid = c$uid,
		                $id  = c$id);
		Conn::register_removal_hook(c, finalize_radius);
		}

	switch ( RADIUS::msg_types[result$code] )
		{
		case "Access-Request":
			if ( result?$attributes )
				{

				if ( ! c$radius?$username && 1 in result$attributes )
					c$radius$username = result$attributes[1][0];


				if ( ! c$radius?$mac && 31 in result$attributes )
					c$radius$mac = normalize_mac(result$attributes[31][0]);


				if ( ! c$radius?$tunnel_client && 66 in result$attributes )
					c$radius$tunnel_client = result$attributes[66][0];


				if ( ! c$radius?$connect_info && 77 in result$attributes )
					c$radius$connect_info = result$attributes[77][0];
				}
			break;

		case "Access-Challenge":
			if ( result?$attributes )
				{

				if ( ! c$radius?$framed_addr && 8 in result$attributes )
					c$radius$framed_addr = raw_bytes_to_v4_addr(result$attributes[8][0]);

				if ( ! c$radius?$reply_msg && 18 in result$attributes )
					c$radius$reply_msg = result$attributes[18][0];
				}
			break;

		case "Access-Accept":
			c$radius$result = "success";
			break;

		case "Access-Reject":
			c$radius$result = "failed";
			break;







		}
	}

event radius_message(c: connection, result: RADIUS::Message) &priority=-5
	{
	if ( c$radius?$result )
		{
		local ttl = network_time() - c$radius$ts;
		if ( ttl != 0secs )
			c$radius$ttl = ttl;

		Log::write(RADIUS::LOG, c$radius);

		delete c$radius;
		}
	}

hook finalize_radius(c: connection)
	{
	if ( c?$radius && ! c$radius$logged )
		{
		c$radius$result = "unknown";
		Log::write(RADIUS::LOG, c$radius);
		}
	}
