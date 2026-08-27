

module NetControl;

@load ./main

export {
	redef enum Log::ID += { SHUNT };

	global log_policy_shunt: Log::PolicyHook;










	global shunt_flow: function(f: flow_id, t: interval, location: string &default="") : string;

	type ShuntInfo: record {

		ts: time &log;

		rule_id: string  &log;

		f: flow_id &log;

		expire: interval &log;

		location: string &log &optional;
	};



	global log_netcontrol_shunt: event(rec: ShuntInfo);
}

event zeek_init() &priority=5
	{
	Log::create_stream(NetControl::SHUNT, Log::Stream($columns=ShuntInfo, $ev=log_netcontrol_shunt, $path="netcontrol_shunt", $policy=log_policy_shunt));
	}

function shunt_flow(f: flow_id, t: interval, location: string &default="") : string
	{
	local flow = NetControl::Flow(
		$src_h=f$src_h as subnet,
		$src_p=f$src_p,
		$dst_h=f$dst_h as subnet,
		$dst_p=f$dst_p
	);
	local e = Entity($ty=FLOW, $flow=flow);
	local r = Rule($ty=DROP, $target=MONITOR, $entity=e, $expire=t, $location=location);

	local id = add_rule(r);


	if ( id == "" )
		return id;

	local log = ShuntInfo($ts=network_time(), $rule_id=id, $f=f, $expire=t);
	if ( location != "" )
		log$location=location;

	Log::write(SHUNT, log);

	return id;
	}
