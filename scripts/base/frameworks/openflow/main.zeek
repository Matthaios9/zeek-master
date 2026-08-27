









module OpenFlow;

@load ./consts
@load ./types

export {









	global flow_mod: function(controller: Controller, match: ofp_match, flow_mod: ofp_flow_mod): bool;






	global flow_clear: function(controller: Controller): bool;










	global flow_mod_success: event(name: string, match: ofp_match, flow_mod: ofp_flow_mod, msg: string &default="");










	global flow_mod_failure: event(name: string, match: ofp_match, flow_mod: ofp_flow_mod, msg: string &default="");




















	global flow_removed: event(name: string, match: ofp_match, cookie: count, priority: count, reason: count, duration_sec: count, idle_timeout: count, packet_count: count, byte_count: count);









	global match_conn: function(id: conn_id, reverse: bool &default=F): ofp_match;










	global get_cookie_uid: function(cookie: count): count;






	global get_cookie_gid: function(cookie: count): count;






	global generate_cookie: function(cookie: count &default=0): count;









	global register_controller: function(tpe: OpenFlow::Plugin, name: string, controller: Controller);






	global unregister_controller: function(controller: Controller);




	global controller_init_done: function(controller: Controller);






	global OpenFlow::controller_activated: event(name: string, controller: Controller);






	global lookup_controller: function(name: string): vector of Controller;
}

global name_to_controller: table[string] of Controller;


function match_conn(id: conn_id, reverse: bool &default=F): ofp_match
	{
	local dl_type = ETH_IPv4;
	local proto = IP_TCP;

	local orig_h: addr;
	local orig_p: port;
	local resp_h: addr;
	local resp_p: port;

	if ( reverse == F )
		{
		orig_h = id$orig_h;
		orig_p = id$orig_p;
		resp_h = id$resp_h;
		resp_p = id$resp_p;
		}
	else
		{
		orig_h = id$resp_h;
		orig_p = id$resp_p;
		resp_h = id$orig_h;
		resp_p = id$orig_p;
		}

		if ( is_v6_addr(orig_h) )
			dl_type = ETH_IPv6;

		if ( is_udp_port(orig_p) )
			proto = IP_UDP;
		else if ( is_icmp_port(orig_p) )
			proto = IP_ICMP;

		return ofp_match(
			$dl_type=dl_type,
			$nw_proto=proto,
			$nw_src=orig_h as subnet,
			$tp_src=orig_p as count,
			$nw_dst=resp_h as subnet,
			$tp_dst=resp_p as count
		);
	}




function generate_cookie(cookie: count &default=0): count
	{
	local c = ZEEK_COOKIE_ID * COOKIE_BID_START;

	if ( cookie >= COOKIE_UID_SIZE )
		Reporter::warning(fmt("The given cookie uid '%d' is > 32bit and will be discarded", cookie));
	else
		c += cookie;

	return c;
	}


function is_valid_cookie(cookie: count): bool
	{
	if ( cookie / COOKIE_BID_START == ZEEK_COOKIE_ID )
		return T;

	Reporter::warning(fmt("The given Openflow cookie '%d' is not valid", cookie));

	return F;
	}

function get_cookie_uid(cookie: count): count
	{
	if( is_valid_cookie(cookie) )
		return (cookie - ((cookie / COOKIE_GID_START) * COOKIE_GID_START));

	return INVALID_COOKIE;
	}

function get_cookie_gid(cookie: count): count
	{
	if( is_valid_cookie(cookie) )
		return (
			(cookie	- (COOKIE_BID_START * ZEEK_COOKIE_ID) -
			(cookie - ((cookie / COOKIE_GID_START) * COOKIE_GID_START))) /
			COOKIE_GID_START
		);

	return INVALID_COOKIE;
	}

function controller_init_done(controller: Controller)
	{
	if ( controller$state$_name !in name_to_controller )
		{
		Reporter::error(fmt("Openflow initialized unknown plugin %s successfully?", controller$state$_name));
		return;
		}

	controller$state$_activated = T;
	event OpenFlow::controller_activated(controller$state$_name, controller);
	}



function register_controller_impl(tpe: OpenFlow::Plugin, name: string, controller: Controller)
	{
	if ( controller$state$_name in name_to_controller )
		{
		Reporter::error(fmt("OpenFlow Controller %s was already registered. Ignored duplicate registration", controller$state$_name));
		return;
		}

	name_to_controller[controller$state$_name] = controller;

	if ( controller?$init )
		controller$init(controller$state);
	else
		controller_init_done(controller);
	}

function unregister_controller_impl(controller: Controller)
	{
	if ( controller$state$_name in name_to_controller )
		delete name_to_controller[controller$state$_name];
	else
		Reporter::error("OpenFlow Controller %s was not registered in unregister.");

	if ( controller?$destroy )
		controller$destroy(controller$state);
	}

function lookup_controller_impl(name: string): vector of Controller
	{
	if ( name in name_to_controller )
		return vector(name_to_controller[name]);
	else
		return vector();
	}
