




module ConnPolling;

export {















	global watch: function(c: connection,
			       callback: function(c: connection, cnt: count): interval,
			       cnt: count, i: interval);
}

event ConnPolling::check(id: conn_id,
			 callback: function(c: connection, cnt: count): interval,
			 cnt: count)
	{
	if ( ! connection_exists(id) )
		return;

	local c = lookup_connection(id);

	local next_interval = callback(c, cnt);
	if ( next_interval < 0secs )
		return;

	watch(c, callback, cnt + 1, next_interval);
	}

function watch(c: connection,
	       callback: function(c: connection, cnt: count): interval,
	       cnt: count, i: interval)
	{
	local id = c$id;
	schedule i { ConnPolling::check(id, callback, cnt) };
	}
