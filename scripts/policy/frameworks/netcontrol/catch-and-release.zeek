

@load base/frameworks/netcontrol
@load base/frameworks/cluster

module NetControl;

export {

	redef enum Log::ID += { CATCH_RELEASE };

	global log_policy_catch_release: Log::PolicyHook;



	type BlockInfo: record {

		block_until: time &optional;

		watch_until: time;

		num_reblocked: count &default=0;

		current_interval: count;

		current_block_id: string;

		location: string &optional;
	};



	type CatchReleaseActions: enum {

		INFO,



		ADDED,

		DROP_REQUESTED,

		DROPPED,

		UNBLOCK,

		FORGOTTEN,

		SEEN_AGAIN
	};


	type CatchReleaseInfo: record {

		ts: time &log;

		rule_id: string &log &optional;

		ip: addr &log;

		action: CatchReleaseActions &log;

		block_interval: interval &log &optional;

		watch_interval: interval &log &optional;

		blocked_until: time &log &optional;

		watched_until: time &log &optional;

		num_blocked: count &log &optional;

		location: string &log &optional;

		message: string &log &optional;

		plugin: string		&log &optional;
	};


















	global drop_address_catch_release: function(a: addr, location: string &default="") : BlockInfo;












	global unblock_address_catch_release: function(a: addr, reason: string &default="") : bool;







	global catch_release_seen: function(a: addr);












	global get_catch_release_info: function(a: addr) : BlockInfo;







	global catch_release_forgotten: event(a: addr, bi: BlockInfo);




	const watch_connections = T &redef;



	option catch_release_warn_blocked_ip_encountered = F;



	const catch_release_intervals: vector of interval = vector(10min, 1hr, 24hrs, 7days) &redef;



	global log_netcontrol_catch_release: event(rec: CatchReleaseInfo);


	global catch_release_block_new: event(a: addr, b: BlockInfo);
	global catch_release_block_delete: event(a: addr);
	global catch_release_add: event(a: addr, location: string);
	global catch_release_delete: event(a: addr, reason: string);
	global catch_release_encountered: event(a: addr);
}


global catch_release_recently_notified: set[addr] &create_expire=30secs;

event zeek_init() &priority=5
	{
	Log::create_stream(NetControl::CATCH_RELEASE, Log::Stream($columns=CatchReleaseInfo, $ev=log_netcontrol_catch_release, $path="netcontrol_catch_release", $policy=log_policy_catch_release));
	}

function get_watch_interval(current_interval: count): interval
	{
	if ( (current_interval + 1) in catch_release_intervals )
		return catch_release_intervals[current_interval+1];
	else
		return catch_release_intervals[current_interval];
	}

function populate_log_record(ip: addr, bi: BlockInfo, action: CatchReleaseActions): CatchReleaseInfo
	{
	local log = CatchReleaseInfo($ts=network_time(), $ip=ip, $action=action,
	        $block_interval=catch_release_intervals[bi$current_interval],
	        $watch_interval=get_watch_interval(bi$current_interval),
	        $watched_until=bi$watch_until,
	        $num_blocked=bi$num_reblocked+1
	        );

	if ( bi?$block_until )
		log$blocked_until = bi$block_until;

	if ( bi?$current_block_id && bi$current_block_id != "" )
		log$rule_id = bi$current_block_id;

	if ( bi?$location )
		log$location = bi$location;

	return log;
	}

function per_block_interval(t: table[addr] of BlockInfo, idx: addr): interval
	{
	local remaining_time = t[idx]$watch_until - network_time();
	if ( remaining_time < 0secs )
		remaining_time = 0secs;

@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) )
	if ( remaining_time == 0secs )
		{
		local log = populate_log_record(idx, t[idx], FORGOTTEN);
		Log::write(CATCH_RELEASE, log);

		event NetControl::catch_release_forgotten(idx, t[idx]);
		}
@endif

	return remaining_time;
	}




global blocks: table[addr] of BlockInfo = {}
	&create_expire=0secs
	&expire_func=per_block_interval;

function cr_check_rule(r: Rule): bool &is_used
	{
	if ( r$ty == DROP && r$entity$ty == ADDRESS )
		{
		local ip = r$entity$ip;
		if ( ( is_v4_subnet(ip) && subnet_width(ip) == 32 ) || ( is_v6_subnet(ip) && subnet_width(ip) == 128 ) )
			{
			if ( ip as addr in blocks )
				return T;
			}
		}

		return F;
	}

@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) )

event rule_added(r: Rule, p: PluginState, msg: string)
	{
	if ( !cr_check_rule(r) )
		return;

	local ip = r$entity$ip as addr;
	local bi = blocks[ip];

	local log = populate_log_record(ip, bi, DROPPED);
	log$plugin = p$plugin$name(p);
	if ( msg != "" )
		log$message = msg;
	Log::write(CATCH_RELEASE, log);
	}

event rule_exists(r: Rule, p: PluginState, msg: string)
	{
	if ( !cr_check_rule(r) )
		return;

	local ip = r$entity$ip as addr;
	local bi = blocks[ip];

	local log = populate_log_record(ip, bi, INFO);
	log$plugin = p$plugin$name(p);
	local infomsg = "Existing rule encountered while inserting rule";
	log$message = msg + infomsg;
	Log::write(CATCH_RELEASE, log);
	}

event rule_error(r: Rule, p: PluginState, msg: string)
	{
	if ( !cr_check_rule(r) )
		return;

	local ip = r$entity$ip as addr;
	local bi = blocks[ip];

	local log = populate_log_record(ip, bi, INFO);
	log$plugin = p$plugin$name(p);
	log$message = "Error occurred during rule operation: " + msg;
	Log::write(CATCH_RELEASE, log);
	}

event rule_timeout(r: Rule, i: FlowInfo, p: PluginState)
	{
	if ( !cr_check_rule(r) )
		return;

	local ip = r$entity$ip as addr;
	local bi = blocks[ip];

	local log = populate_log_record(ip, bi, UNBLOCK);
	log$plugin = p$plugin$name(p);
	if ( bi?$block_until )
		{
		local difference: interval = network_time() - bi$block_until;
		if ( difference as double > 60 || difference as double < -60 )
			log$message = fmt("Difference between network_time and block time excessive: %f", difference);
		}

	Log::write(CATCH_RELEASE, log);
	}

@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event catch_release_add(a: addr, location: string)
	{
	drop_address_catch_release(a, location);
	}

event catch_release_delete(a: addr, reason: string)
	{
	unblock_address_catch_release(a, reason);
	}

event catch_release_encountered(a: addr)
	{
	catch_release_seen(a);
	}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event catch_release_block_new(a: addr, b: BlockInfo)
	{
	blocks[a] = b;
	}

event catch_release_block_delete(a: addr)
	{
	if ( a in blocks )
		delete blocks[a];
	}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
@endif

function get_catch_release_info(a: addr): BlockInfo
	{
	if ( a in blocks )
		return blocks[a];

	return BlockInfo($watch_until=0 as time, $current_interval=0, $current_block_id="");
	}

function drop_address_catch_release(a: addr, location: string &default=""): BlockInfo
	{
	local bi: BlockInfo;
	local log: CatchReleaseInfo;

	if ( a in blocks )
		{
		log = populate_log_record(a, blocks[a], INFO);
		log$message = "Already blocked using catch-and-release - ignoring duplicate";
		Log::write(CATCH_RELEASE, log);

		return blocks[a];
		}

	local e = Entity($ty=ADDRESS, $ip=a as subnet);
	if ( [e,DROP] in rule_entities )
		{
		local r = rule_entities[e,DROP];

		bi = BlockInfo($watch_until=network_time()+catch_release_intervals[1], $current_interval=0, $current_block_id=r$id);
		if ( location != "" )
			bi$location = location;
@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) )
		log = populate_log_record(a, bi, ADDED);
		log$message = "Address already blocked outside of catch-and-release. Catch and release will monitor and only actively block if it appears in network traffic.";
		Log::write(CATCH_RELEASE, log);
		blocks[a] = bi;
@if ( Cluster::is_enabled() )
		Cluster::publish(Cluster::worker_topic, NetControl::catch_release_block_new, a, bi);
@endif
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		Cluster::publish(Cluster::manager_topic, NetControl::catch_release_add, a, location);
@endif
		return bi;
		}


	local block_interval = catch_release_intervals[0];

@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled()  && Cluster::local_node_type() == Cluster::MANAGER ) )
	local ret = drop_address(a, block_interval, location);

	if ( ret != "" )
		{
		bi = BlockInfo($watch_until=network_time()+catch_release_intervals[1], $block_until=network_time()+block_interval, $current_interval=0, $current_block_id=ret);
		if ( location != "" )
			bi$location = location;
		blocks[a] = bi;
@if ( Cluster::is_enabled() )
		Cluster::publish(Cluster::worker_topic, NetControl::catch_release_block_new, a, bi);
@endif
		log = populate_log_record(a, bi, DROP_REQUESTED);
		Log::write(CATCH_RELEASE, log);
		return bi;
		}
	Reporter::error(fmt("Catch and release could not add block for %s; failing.", a));
	return BlockInfo($watch_until=0 as time, $current_interval=0, $current_block_id="");
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
	bi = BlockInfo($watch_until=network_time()+catch_release_intervals[1], $block_until=network_time()+block_interval, $current_interval=0, $current_block_id="");
	Cluster::publish(Cluster::manager_topic, NetControl::catch_release_add, a, location);
	return bi;
@endif

	}

function unblock_address_catch_release(a: addr, reason: string &default=""): bool
	{
	if ( a !in blocks )
		return F;

@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) )
	local bi = blocks[a];
	local log = populate_log_record(a, bi, UNBLOCK);
	if ( reason != "" )
		log$message = reason;
	Log::write(CATCH_RELEASE, log);
	delete blocks[a];
	if ( bi?$block_until && bi$block_until > network_time() && bi$current_block_id != "" )
		remove_rule(bi$current_block_id, reason);
@endif
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
	Cluster::publish(Cluster::worker_topic, NetControl::catch_release_block_delete, a);
@endif
@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
	Cluster::publish(Cluster::manager_topic, NetControl::catch_release_delete, a, reason);
@endif

	return T;
	}

function catch_release_seen(a: addr)
	{
	if ( a in blocks )
		{
@if ( ! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) )
		local bi = blocks[a];
		local log: CatchReleaseInfo;
		local e = Entity($ty=ADDRESS, $ip=a as subnet);

		if ( [e,DROP] in rule_entities )
			{
			if ( catch_release_warn_blocked_ip_encountered == F )
				return;


			log = populate_log_record(a, bi, INFO);
			log$action = INFO;
			log$message = "Block seen while in rule_entities. No action taken.";
			Log::write(CATCH_RELEASE, log);
			return;
			}



		local try = bi$current_interval;
		if ( (try+1) in catch_release_intervals )
			++try;

		bi$current_interval = try;
		if ( (try+1) in catch_release_intervals )
			bi$watch_until = network_time() + catch_release_intervals[try+1];
		else
			bi$watch_until = network_time() + catch_release_intervals[try];

		bi$block_until = network_time() + catch_release_intervals[try];
		++bi$num_reblocked;

		local block_interval = catch_release_intervals[try];
		local location = "";
		if ( bi?$location )
			location = bi$location;
		local drop = drop_address(a, block_interval, fmt("Re-drop by catch-and-release: %s", location));
		bi$current_block_id = drop;

		blocks[a] = bi;

		log = populate_log_record(a, bi, SEEN_AGAIN);
		Log::write(CATCH_RELEASE, log);
@endif
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
		Cluster::publish(Cluster::worker_topic, NetControl::catch_release_block_new, a, bi);
@endif
@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		if ( a in catch_release_recently_notified )
			return;

		Cluster::publish(Cluster::manager_topic, NetControl::catch_release_encountered, a);
		add catch_release_recently_notified[a];
@endif

		return;
		}

	return;
	}

event new_connection(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event connection_established(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event partial_connection(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event connection_attempt(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event connection_rejected(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event connection_reset(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}

event connection_pending(c: connection)
	{
	if ( watch_connections )
		catch_release_seen(c$id$orig_h);
	}
