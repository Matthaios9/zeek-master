











@load ./plugin
@load ./types

module NetControl;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;











	global activate: function(p: PluginState, priority: int);



	global NetControl::init: event();



	global NetControl::init_done: event();

















	global whitelist_address: function(a: addr, t: interval, location: string &default="") : string;










	global whitelist_subnet: function(s: subnet, t: interval, location: string &default="") : string;












	global redirect_flow: function(f: flow_id, out_port: count, t: interval, location: string &default="") : string;
















	global quarantine_host: function(infected: addr, dns: addr, quarantine: addr, t: interval, location: string &default="") : vector of string;


	global clear: function();


















	global add_rule: function(r: Rule) : string;












	global remove_rule: function(id: string, reason: string &default="") : bool;












	global delete_rule: function(id: string, reason: string &default="") : bool;










	global find_rules_addr: function(ip: addr) : vector of Rule;


















	global find_rules_subnet: function(sn: subnet) : vector of Rule;










	global rule_added: event(r: Rule, p: PluginState, msg: string &default="");












	global rule_exists: event(r: Rule, p: PluginState, msg: string &default="");










	global rule_removed: event(r: Rule, p: PluginState, msg: string &default="");











	global rule_timeout: event(r: Rule, i: FlowInfo, p: PluginState);








	global rule_error: event(r: Rule, p: PluginState, msg: string &default="");










	global rule_new: event(r: Rule);








	global rule_destroyed: event(r: Rule);






	global NetControl::rule_policy: hook(r: Rule);













	global NetControl::rule_added_policy: hook(r: Rule, p: PluginState, exists: bool, msg: string);







	global plugin_activated: function(p: PluginState);


	type InfoCategory: enum {

		MESSAGE,

		ERROR,

		RULE
	};


	type InfoState: enum {
		REQUESTED,
		SUCCEEDED,
		EXISTS,
		FAILED,
		REMOVED,
		TIMEOUT,
	};


	type Info: record {

		ts: time		&log;

		rule_id: string  &log &optional;

		category: InfoCategory	&log &optional;

		cmd: string	&log &optional;

		state: InfoState	&log &optional;

		action: string		&log &optional;

		target: TargetType	&log &optional;

		entity_type: string		&log &optional;

		entity: string		&log &optional;

		mod: string		&log &optional;

		msg: string		&log &optional;

		priority: int &log &optional;

		expire: interval &log &optional;

		location: string	&log &optional;

		plugin: string		&log &optional;
	};



	global log_netcontrol: event(rec: Info);
}

redef record Rule += {

	_plugin_ids: set[count] &default=count_set();

	_active_plugin_ids: set[count] &default=count_set();

	_no_expire_plugins: set[count] &default=count_set();

	_added: bool &default=F;
};




global plugins_active: bool = F;



global zeek_init_done: bool = F;


global rule_counter: count = 1;
global plugin_counter: count = 1;


global plugins: vector of PluginState;
global plugin_ids: table[count] of PluginState;


global rules: table[string] of Rule;


global rules_by_subnets: table[subnet] of set[string];



global rule_entities: table[Entity, RuleType] of Rule;

event zeek_init() &priority=5
	{
	Log::create_stream(NetControl::LOG, Log::Stream($columns=Info, $ev=log_netcontrol, $path="netcontrol", $policy=log_policy));
	}

function entity_to_info(info: Info, e: Entity)
	{
	info$entity_type = fmt("%s", e$ty);

	switch ( e$ty ) {
		case ADDRESS:
			info$entity = fmt("%s", e$ip);
			break;

		case CONNECTION:
			info$entity = fmt("%s/%d<->%s/%d",
					  e$conn$orig_h, e$conn$orig_p,
					  e$conn$resp_h, e$conn$resp_p);
			break;

		case FLOW:
			local ffrom_ip = "*";
			local ffrom_port = "*";
			local fto_ip = "*";
			local fto_port = "*";
			local ffrom_mac = "*";
			local fto_mac = "*";
			if ( e$flow?$src_h )
				ffrom_ip = cat(e$flow$src_h);
			if ( e$flow?$src_p )
				ffrom_port = fmt("%d", e$flow$src_p);
			if ( e$flow?$dst_h )
				fto_ip = cat(e$flow$dst_h);
			if ( e$flow?$dst_p )
				fto_port = fmt("%d", e$flow$dst_p);
			info$entity = fmt("%s/%s->%s/%s",
					  ffrom_ip, ffrom_port,
					  fto_ip, fto_port);
			if ( e$flow?$src_m || e$flow?$dst_m )
				{
				if ( e$flow?$src_m )
					ffrom_mac = e$flow$src_m;
				if ( e$flow?$dst_m )
					fto_mac = e$flow$dst_m;

				info$entity = fmt("%s (%s->%s)", info$entity, ffrom_mac, fto_mac);
				}
			break;

		case MAC:
			info$entity = e$mac;
			break;

		default:
			info$entity = "<unknown entity type>";
			break;
		}
	}

function rule_to_info(info: Info, r: Rule)
	{
	info$action = fmt("%s", r$ty);
	info$target = r$target;
	info$rule_id = r$id;
	info$expire = r$expire;
	info$priority = r$priority;

	if ( r?$location && r$location != "" )
		info$location = r$location;

	if ( r$ty == REDIRECT )
		info$mod = fmt("-> %d", r$out_port);

	if ( r$ty == MODIFY )
		{
		local mfrom_ip = "_";
		local mfrom_port = "_";
		local mto_ip = "_";
		local mto_port = "_";
		local mfrom_mac = "_";
		local mto_mac = "_";
		if ( r$mod?$src_h )
			mfrom_ip = cat(r$mod$src_h);
		if ( r$mod?$src_p )
			mfrom_port = fmt("%d", r$mod$src_p);
		if ( r$mod?$dst_h )
			mto_ip = cat(r$mod$dst_h);
		if ( r$mod?$dst_p )
			mto_port = fmt("%d", r$mod$dst_p);

		if ( r$mod?$src_m )
			mfrom_mac = r$mod$src_m;
		if ( r$mod?$dst_m )
			mto_mac = r$mod$dst_m;

		info$mod = fmt("Src: %s/%s (%s) Dst: %s/%s (%s)",
			mfrom_ip, mfrom_port, mfrom_mac, mto_ip, mto_port, mto_mac);

		if ( r$mod?$redirect_port )
			info$mod = fmt("%s -> %d", info$mod, r$mod$redirect_port);

		}

	entity_to_info(info, r$entity);
	}

function log_msg(msg: string, p: PluginState)
	{
	Log::write(LOG, Info($ts=network_time(), $category=MESSAGE, $msg=msg, $plugin=p$plugin$name(p)));
	}

function log_error(msg: string, p: PluginState)
	{
	Log::write(LOG, Info($ts=network_time(), $category=ERROR, $msg=msg, $plugin=p$plugin$name(p)));
	}

function log_msg_no_plugin(msg: string)
	{
	Log::write(LOG, Info($ts=network_time(), $category=MESSAGE, $msg=msg));
	}

function log_rule(r: Rule, cmd: string, state: InfoState, p: PluginState, msg: string &default="")
	{
	local info = Info($ts=network_time());
	info$category = RULE;
	info$cmd = cmd;
	info$state = state;
	info$plugin = p$plugin$name(p);
	if ( msg != "" )
		info$msg = msg;

	rule_to_info(info, r);

	Log::write(LOG, info);
	}

function log_rule_error(r: Rule, msg: string, p: PluginState)
	{
	local info = Info($ts=network_time(), $category=ERROR, $msg=msg, $plugin=p$plugin$name(p));
	rule_to_info(info, r);
	Log::write(LOG, info);
	}

function log_rule_no_plugin(r: Rule, state: InfoState, msg: string)
	{
	local info  = Info($ts=network_time());
	info$category = RULE;
	info$state = state;
	info$msg = msg;

	rule_to_info(info, r);

	Log::write(LOG, info);
	}

function whitelist_address(a: addr, t: interval, location: string &default="") : string
	{
	local e = Entity($ty=ADDRESS, $ip=a as subnet);
	local r = Rule($ty=WHITELIST, $priority=whitelist_priority, $target=FORWARD, $entity=e, $expire=t, $location=location);

	return add_rule(r);
	}

function whitelist_subnet(s: subnet, t: interval, location: string &default="") : string
	{
	local e = Entity($ty=ADDRESS, $ip=s);
	local r = Rule($ty=WHITELIST, $priority=whitelist_priority, $target=FORWARD, $entity=e, $expire=t, $location=location);

	return add_rule(r);
	}


function redirect_flow(f: flow_id, out_port: count, t: interval, location: string &default="") : string
	{
	local flow = NetControl::Flow(
		$src_h=f$src_h as subnet,
		$src_p=f$src_p,
		$dst_h=f$dst_h as subnet,
		$dst_p=f$dst_p
	);
	local e = Entity($ty=FLOW, $flow=flow);
	local r = Rule($ty=REDIRECT, $target=FORWARD, $entity=e, $expire=t, $location=location, $out_port=out_port);

	return add_rule(r);
	}

function quarantine_host(infected: addr, dns: addr, quarantine: addr, t: interval, location: string &default="") : vector of string
	{
	local orules: vector of string = vector();
	local edrop = Entity($ty=FLOW, $flow=Flow($src_h=infected as subnet));
	local rdrop = Rule($ty=DROP, $target=FORWARD, $entity=edrop, $expire=t, $location=location);
	orules += add_rule(rdrop);

	local todnse = Entity($ty=FLOW, $flow=Flow($src_h=infected as subnet, $dst_h=dns as subnet, $dst_p=53/udp));
	local todnsr = Rule($ty=MODIFY, $target=FORWARD, $entity=todnse, $expire=t, $location=location, $mod=FlowMod($dst_h=quarantine), $priority=+5);
	orules += add_rule(todnsr);

	local fromdnse = Entity($ty=FLOW, $flow=Flow($src_h=dns as subnet, $src_p=53/udp, $dst_h=infected as subnet));
	local fromdnsr = Rule($ty=MODIFY, $target=FORWARD, $entity=fromdnse, $expire=t, $location=location, $mod=FlowMod($src_h=dns), $priority=+5);
	orules += add_rule(fromdnsr);

	local wle = Entity($ty=FLOW, $flow=Flow($src_h=infected as subnet, $dst_h=quarantine as subnet, $dst_p=80/tcp));
	local wlr = Rule($ty=WHITELIST, $target=FORWARD, $entity=wle, $expire=t, $location=location, $priority=+5);
	orules += add_rule(wlr);

	return orules;
	}

function check_plugins()
	{
	if ( plugins_active )
		return;

	local all_active = T;
	for ( i in plugins )
		{
		local p = plugins[i];
		if ( p$_activated == F )
			all_active = F;
		}

	if ( all_active )
		{
		plugins_active = T;


		if ( |plugins| > 0 )
			log_msg_no_plugin("plugin initialization done");

		event NetControl::init_done();
		}
	}

function plugin_activated(p: PluginState)
	{
	local id = p$_id;
	if ( id !in plugin_ids )
		{
		log_error("unknown plugin activated", p);
		return;
		}


	if ( plugin_ids[id]$_activated == T )
		return;

	plugin_ids[id]$_activated = T;
	log_msg("activation finished", p);

	if ( zeek_init_done )
		check_plugins();
	}

event zeek_init() &priority=-5
	{
	event NetControl::init();
	}

event NetControl::init() &priority=-20
	{
	zeek_init_done = T;

	check_plugins();

	if ( plugins_active == F )
		log_msg_no_plugin("waiting for plugins to initialize");
	}



function activate_impl(p: PluginState, priority: int)
	{
	p$_priority = priority;
	plugins += p;
	sort(plugins, function(p1: PluginState, p2: PluginState) : int { return p2$_priority - p1$_priority; });

	plugin_ids[plugin_counter] = p;
	p$_id = plugin_counter;
	++plugin_counter;


	if ( p$plugin?$init )
		{
		log_msg(fmt("activating plugin with priority %d", priority), p);
		p$plugin$init(p);
		}
	else
		{

		plugin_activated(p);
		}

	}

function add_one_subnet_entry(s: subnet, r: Rule)
	{
	if ( ! check_subnet(s, rules_by_subnets) )
		rules_by_subnets[s] = set(r$id);
	else
		add rules_by_subnets[s][r$id];
	}

function add_subnet_entry(rule: Rule)
	{
	local e = rule$entity;
	if ( e$ty == ADDRESS )
		{
		add_one_subnet_entry(e$ip, rule);
		}
	else if ( e$ty == CONNECTION )
		{
		add_one_subnet_entry(e$conn$orig_h as subnet, rule);
		add_one_subnet_entry(e$conn$resp_h as subnet, rule);
		}
	else if ( e$ty == FLOW )
		{
		if ( e$flow?$src_h )
			add_one_subnet_entry(e$flow$src_h, rule);
		if ( e$flow?$dst_h )
			add_one_subnet_entry(e$flow$dst_h, rule);
		}
	}

function remove_one_subnet_entry(s: subnet, r: Rule)
	{
	if ( ! check_subnet(s, rules_by_subnets) )
		return;

	if ( r$id !in rules_by_subnets[s] )
		return;

	delete rules_by_subnets[s][r$id];
	if ( |rules_by_subnets[s]| == 0 )
		delete rules_by_subnets[s];
	}

function remove_subnet_entry(rule: Rule)
	{
	local e = rule$entity;
	if ( e$ty == ADDRESS )
		{
		remove_one_subnet_entry(e$ip, rule);
		}
	else if ( e$ty == CONNECTION )
		{
		remove_one_subnet_entry(e$conn$orig_h as subnet, rule);
		remove_one_subnet_entry(e$conn$resp_h as subnet, rule);
		}
	else if ( e$ty == FLOW )
		{
		if ( e$flow?$src_h )
			remove_one_subnet_entry(e$flow$src_h, rule);
		if ( e$flow?$dst_h )
			remove_one_subnet_entry(e$flow$dst_h, rule);
		}
	}

function find_rules_subnet(sn: subnet) : vector of Rule
	{
	local ret: vector of Rule = vector();

	local matches = matching_subnets(sn, rules_by_subnets);

	for ( m in matches )
		{
		local sn_entry = matches[m];
		local rule_ids = rules_by_subnets[sn_entry];
		for ( rule_id in rule_ids )
			{
			if ( rule_id in rules )
				ret += rules[rule_id];
			else
				Reporter::error("find_rules_subnet - internal data structure error, missing rule");
			}
		}

		return ret;
	}

function find_rules_addr(ip: addr) : vector of Rule
	{
	return find_rules_subnet(ip as subnet);
	}

function add_rule_impl(rule: Rule) : string
	{
	if ( ! plugins_active )
		{
		log_rule_no_plugin(rule, FAILED, "plugins not initialized yet");
		return "";
		}

	rule$cid = ++rule_counter;

	if ( ! rule?$id || rule$id == "" )
		rule$id = cat(rule$cid);

	if ( ! hook NetControl::rule_policy(rule) )
		return "";

	if ( [rule$entity, rule$ty] in rule_entities )
		{
		log_rule_no_plugin(rule, FAILED, "discarded duplicate insertion");
		return "";
		}

	local accepted = F;
	local priority: int = +0;

	for ( i in plugins )
		{
		local p = plugins[i];

		if ( p$_activated == F )
			next;



		if ( accepted == T && p$_priority != priority )
			break;

		if ( p$plugin$add_rule(p, rule) )
			{
			accepted = T;
			priority = p$_priority;
			log_rule(rule, "ADD", REQUESTED, p);

			add rule$_plugin_ids[p$_id];
			}
		}

	if ( accepted )
		{
		rules[rule$id] = rule;
		rule_entities[rule$entity, rule$ty] = rule;

		add_subnet_entry(rule);

		event NetControl::rule_new(rule);

		return rule$id;
		}

	log_rule_no_plugin(rule, FAILED, "not supported");
	return "";
	}

function rule_cleanup(r: Rule)
	{
	if ( |r$_active_plugin_ids| > 0 )
		return;

	remove_subnet_entry(r);

	delete rule_entities[r$entity, r$ty];
	delete rules[r$id];

	event NetControl::rule_destroyed(r);
	}

function delete_rule_impl(id: string, reason: string): bool
	{
	if ( id !in rules )
		{
		Reporter::error(fmt("Rule %s does not exist in NetControl::delete_rule", id));
		return F;
		}

	local rule = rules[id];

	rule$_active_plugin_ids = set();

	rule_cleanup(rule);
	if ( reason != "" )
		log_rule_no_plugin(rule, REMOVED, fmt("delete_rule: %s", reason));
	else
		log_rule_no_plugin(rule, REMOVED, "delete_rule");

	return T;
	}

function remove_rule_plugin(r: Rule, p: PluginState, reason: string &default=""): bool
	{
	local success = T;

	if ( ! p$plugin$remove_rule(p, r, reason) )
		{

		if ( reason != "" )
			log_rule_error(r, fmt("remove failed (original reason: %s)", reason), p);
		else
			log_rule_error(r, "remove failed", p);
		success = F;
		}
		else
		{
		log_rule(r, "REMOVE", REQUESTED, p, reason);
		}

	return success;
	}

function remove_rule_impl(id: string, reason: string) : bool
	{
	if ( id !in rules )
		{
		Reporter::error(fmt("Rule %s does not exist in NetControl::remove_rule", id));
		return F;
		}

	local r = rules[id];

	local success = T;
	for ( plugin_id in r$_active_plugin_ids )
		{
		local p = plugin_ids[plugin_id];
		success = remove_rule_plugin(r, p, reason);
		}

	return success;
	}

function rule_expire_impl(r: Rule, p: PluginState) &priority=-5 &is_used
	{

	if ( zeek_is_terminating() )
		return;

	if ( r$id !in rules )

		return;

	local rule = rules[r$id];

	if ( p$_id in rule$_no_expire_plugins )
		{


		delete rule$_active_plugin_ids[p$_id];
		delete rule$_no_expire_plugins[p$_id];
		rule_cleanup(rule);
		}
	else
		event NetControl::rule_timeout(r, FlowInfo(), p);
	}

function rule_added_impl(r: Rule, p: PluginState, exists: bool, msg: string &default="") &is_used
	{
	if ( r$id !in rules )
		{
		log_rule_error(r, "Addition of unknown rule", p);
		return;
		}


	local rule = rules[r$id];
	if ( p$_id !in rule$_plugin_ids )
		{
		log_rule_error(rule, "Rule added to non-responsible plugin", p);
		return;
		}



	if ( exists )
		{
		add rule$_no_expire_plugins[p$_id];
		log_rule(r, "ADD", EXISTS, p, msg);
		}
	else
		log_rule(r, "ADD", SUCCEEDED, p, msg);

	add rule$_active_plugin_ids[p$_id];
	if ( |rule$_plugin_ids| == |rule$_active_plugin_ids| )
		{

		rule$_added = T;
		}

	hook NetControl::rule_added_policy(rule, p, exists, msg);
	}

function rule_removed_impl(r: Rule, p: PluginState, msg: string &default="") &is_used
	{
	if ( r$id !in rules )
		{
		log_rule_error(r, "Removal of non-existing rule", p);
		return;
		}


	local rule = rules[r$id];

	if ( p$_id !in rule$_plugin_ids )
		{
		log_rule_error(r, "Removed from non-assigned plugin", p);
		return;
		}

	if ( p$_id in rule$_active_plugin_ids )
		{
		delete rule$_active_plugin_ids[p$_id];
		}

	log_rule(rule, "REMOVE", SUCCEEDED, p, msg);
	rule_cleanup(rule);
	}

function rule_timeout_impl(r: Rule, i: FlowInfo, p: PluginState) &is_used
	{
	if ( r$id !in rules )
		{
		log_rule_error(r, "Timeout of non-existing rule", p);
		return;
		}

	local rule = rules[r$id];

	local msg = "";
	if ( i?$packet_count )
		msg = fmt("Packets: %d", i$packet_count);
	if ( i?$byte_count )
		{
		if ( msg != "" )
			msg = msg + " ";
		msg = fmt("%sBytes: %s", msg, i$byte_count);
		}

	log_rule(rule, "EXPIRE", TIMEOUT, p, msg);

	if ( ! p$plugin$can_expire )
		{


		remove_rule_plugin(rule, p);
		return;
		}

	if ( p$_id !in rule$_plugin_ids )
		{
		log_rule_error(r, "Timeout from non-assigned plugin", p);
		return;
		}

	if ( p$_id in rule$_active_plugin_ids )
		{
		delete rule$_active_plugin_ids[p$_id];
		}

	rule_cleanup(rule);
	}

function rule_error_impl(r: Rule, p: PluginState, msg: string &default="") &is_used
	{
	if ( r$id !in rules )
		{
		log_rule_error(r, "Error of non-existing rule", p);
		return;
		}

	local rule = rules[r$id];

	log_rule_error(rule, msg, p);



	if ( p$_id !in rule$_plugin_ids )
		{
		log_rule_error(r, "Error from non-assigned plugin", p);
		return;
		}

	if ( p$_id in rule$_active_plugin_ids )
		{

		delete rule$_plugin_ids[p$_id];
		delete rule$_active_plugin_ids[p$_id];
		rule_cleanup(rule);
		}
	else
		{


		delete rule$_plugin_ids[p$_id];
		if ( |rule$_plugin_ids| == 0 )
			{
			rule_cleanup(rule);
			}
		}
	}

function clear()
	{
	for ( id in rules )
		remove_rule(id);
	}
