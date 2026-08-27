






@load base/protocols/conn/removal-hooks

module Tunnel;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;


	type Action: enum {

		DISCOVER,

		CLOSE,


		EXPIRE,
	};


	type Info: record {

		ts:          time         &log;





		uid:         string       &log &optional;


		id:          conn_id      &log;

		tunnel_type: Tunnel::Type &log;

		action:      Action       &log;
	};




	global register_all: function(ecv: EncapsulatingConnVector);




	global register: function(ec: EncapsulatingConn);












	global expire: function(t: table[conn_id] of Info, idx: conn_id): interval;







	global close: function(tunnel: Info, action: Action);



	const expiration_interval = 1hrs &redef;




	global active: table[conn_id] of Info = table() &read_expire=expiration_interval &expire_func=expire;


	global finalize_tunnel: Conn::RemovalHook;
}

event zeek_init() &priority=5
	{
	Log::create_stream(Tunnel::LOG, Log::Stream($columns=Info, $path="tunnel", $policy=log_policy));
	}

function register_all(ecv: EncapsulatingConnVector)
	{
	for ( i in ecv )
		register(ecv[i]);
	}

hook finalize_tunnel(c: connection)
	{
	if ( c$id in active )
		close(active[c$id], CLOSE);
	}

function register(ec: EncapsulatingConn)
	{
	if ( ec$cid !in active )
		{
		local tunnel: Info;
		tunnel$ts = network_time();
		if ( ec?$uid )
			tunnel$uid = ec$uid;
		tunnel$id = ec$cid;
		tunnel$action = DISCOVER;
		tunnel$tunnel_type = ec$tunnel_type;
		active[ec$cid] = tunnel;

		if ( connection_exists(ec$cid) )
			Conn::register_removal_hook(lookup_connection(ec$cid), finalize_tunnel);

		Log::write(LOG, tunnel);
		}
	}

function close(tunnel: Info, action: Action)
	{
	tunnel$action = action;
	tunnel$ts = network_time();
	Log::write(LOG, tunnel);
	delete active[tunnel$id];
	}

function expire(t: table[conn_id] of Info, idx: conn_id): interval
	{
	close(t[idx], EXPIRE);
	return 0secs;
	}

event new_connection(c: connection) &priority=5
	{
	if ( c?$tunnel )
		register_all(c$tunnel);
	}

event tunnel_changed(c: connection, e: EncapsulatingConnVector) &priority=5
	{
	register_all(e);
	}
