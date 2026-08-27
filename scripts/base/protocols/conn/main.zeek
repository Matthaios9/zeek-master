






@load base/utils/site
@load base/utils/strings

module Conn;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;


	type Info: record {

		ts:           time            &log;

		uid:          string          &log;

		id:           conn_id         &log;

		proto:        transport_proto &log;




		service:      string          &log &optional;










		duration:     interval        &log &optional;



		orig_bytes:   count           &log &optional;


		resp_bytes:   count           &log &optional;






































		conn_state:   string          &log &optional;





		local_orig:   bool            &log &optional;





		local_resp:   bool            &log &optional;





		missed_bytes: count           &log &default=0;


































		history:      string          &log &optional;


		orig_pkts:     count      &log &optional;



		orig_ip_bytes: count      &log &optional;


		resp_pkts:     count      &log &optional;



		resp_ip_bytes: count      &log &optional;



		tunnel_parents: set[string] &log &optional;




		ip_proto:   count      &log &optional;
	};



	global log_conn: event(rec: Info);
}

redef record connection += {
	conn: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(Conn::LOG, Log::Stream($columns=Info, $ev=log_conn, $path="conn", $policy=log_policy));
	}

function conn_state(c: connection, trans: transport_proto): string
	{
	local os = c$orig$state;
	local rs = c$resp$state;

	local o_inactive = os == TCP_INACTIVE || os == TCP_PARTIAL;
	local r_inactive = rs == TCP_INACTIVE || rs == TCP_PARTIAL;

	if ( trans == tcp )
		{
		if ( rs == TCP_RESET )
			{
			if ( os == TCP_SYN_SENT || os == TCP_SYN_ACK_SENT ||
			     (os == TCP_RESET &&
			      c$orig$size == 0 && c$resp$size == 0) )
				return "REJ";
			else if ( o_inactive )
				return "RSTRH";
			else
				return "RSTR";
			}
		else if ( os == TCP_RESET )
			{
			if ( r_inactive )
				{
				if ( /\^?S[^HAFGIQ]*R.*/ == c$history )
					return "RSTOS0";

				return "OTH";
				}

			return "RSTO";
			}
		else if ( rs == TCP_CLOSED && os == TCP_CLOSED )
			return "SF";
		else if ( os == TCP_CLOSED )
			return r_inactive ? "SH" : "S2";
		else if ( rs == TCP_CLOSED )
			return o_inactive ? "SHR" : "S3";
		else if ( os == TCP_SYN_SENT && rs == TCP_INACTIVE )
			return "S0";
		else if ( os == TCP_ESTABLISHED && rs == TCP_ESTABLISHED )
			return "S1";
		else
			return "OTH";
		}

	else if ( trans == udp )
		{
		if ( os == UDP_ACTIVE )
			return rs == UDP_ACTIVE ? "SF" : "S0";
		else
			return rs == UDP_ACTIVE ? "SHR" : "OTH";
		}

	else
		return "OTH";
	}


function set_conn(c: connection, eoc: bool)
	{
	if ( ! eoc ) {
		if ( ! c?$conn )
			{
			local p = get_port_transport_proto(c$id$resp_p);
			c$conn = Info($ts=c$start_time, $uid=c$uid, $proto=p);
			}

		c$conn$id=c$id;
		if ( c?$tunnel && |c$tunnel| > 0 )
			{
			if ( ! c$conn?$tunnel_parents )
				c$conn$tunnel_parents = set();
			add c$conn$tunnel_parents[c$tunnel[|c$tunnel|-1]$uid];
			}

		if ( c$id$proto != 65535 )
			c$conn$ip_proto = c$id$proto;

		if( |Site::local_nets| > 0 )
			{
			c$conn$local_orig = Site::is_local_addr(c$id$orig_h);
			c$conn$local_resp = Site::is_local_addr(c$id$resp_h);
			}
		}
	else
		{
		if ( c$duration > 0secs )
			{
			c$conn$duration=c$duration;
			c$conn$orig_bytes=c$orig$size;
			c$conn$resp_bytes=c$resp$size;
			}
		if ( c$orig?$num_pkts )
			{


			c$conn$orig_pkts = c$orig$num_pkts;
			c$conn$orig_ip_bytes = c$orig$num_bytes_ip;
			c$conn$resp_pkts = c$resp$num_pkts;
			c$conn$resp_ip_bytes = c$resp$num_bytes_ip;
			}

		if ( |c$service| > 0 )
			c$conn$service=to_lower(join_string_set(c$service, ","));

		c$conn$conn_state=conn_state(c, get_port_transport_proto(c$id$resp_p));

		if ( c$history != "" )
			c$conn$history=c$history;
		}
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count) &priority=5
	{
	c$conn$missed_bytes = c$conn$missed_bytes + length;
	}

event tunnel_changed(c: connection, e: EncapsulatingConnVector) &priority=5
	{
	if ( |e| > 0 )
		{
		if ( ! c$conn?$tunnel_parents )
			c$conn$tunnel_parents = set();
		add c$conn$tunnel_parents[e[|e|-1]$uid];
		}
	c$tunnel = e;
	}

event new_connection(c: connection) &priority=100
	{
	set_conn(c, F);
	}

event connection_flipped(c: connection) &priority=5
	{

	if ( c?$conn )
		{
		c$conn$local_orig = Site::is_local_addr(c$id$orig_h);
		c$conn$local_resp = Site::is_local_addr(c$id$resp_h);
		}
	}

event connection_state_remove(c: connection) &priority=5
	{
	set_conn(c, T);
	}

event connection_state_remove(c: connection) &priority=-5
	{
	Log::write(Conn::LOG, c$conn);
	}
