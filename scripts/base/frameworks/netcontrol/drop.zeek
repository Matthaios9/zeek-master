

@load ./main

module NetControl;

export {
	redef enum Log::ID += { DROP_LOG };

	global log_policy_drop: Log::PolicyHook;










	global drop_address: function(a: addr, t: interval, location: string &default="") : string;










	global drop_connection: function(c: conn_id, t: interval, location: string &default="") : string;

	type DropInfo: record {

		ts: time		&log;

		rule_id: string  &log;
		orig_h: addr 	&log;
		orig_p: port 	&log &optional;
		resp_h: addr	&log &optional;
		resp_p: port	&log &optional;

		expire: interval &log;

		location: string	&log &optional;
	};





	global NetControl::drop_rule_policy: hook(r: Rule);



	global log_netcontrol_drop: event(rec: DropInfo);
}

event zeek_init() &priority=5
	{
	Log::create_stream(NetControl::DROP_LOG, Log::Stream($columns=DropInfo, $ev=log_netcontrol_drop, $path="netcontrol_drop", $policy=log_policy_drop));
	}

function drop_connection(c: conn_id, t: interval, location: string &default="") : string
	{
	local e = Entity($ty=CONNECTION, $conn=c);
	local r = Rule($ty=DROP, $target=FORWARD, $entity=e, $expire=t, $location=location);

	if ( ! hook NetControl::drop_rule_policy(r) )
		return "";

	local id = add_rule(r);


	if ( id == "" )
		return id;

	local log = DropInfo($ts=network_time(), $rule_id=id, $orig_h=c$orig_h, $orig_p=c$orig_p, $resp_h=c$resp_h, $resp_p=c$resp_p, $expire=t);

	if ( location != "" )
		log$location=location;

	Log::write(DROP_LOG, log);

	return id;
	}

function drop_address(a: addr, t: interval, location: string &default="") : string
	{
	local e = Entity($ty=ADDRESS, $ip=a as subnet);
	local r = Rule($ty=DROP, $target=FORWARD, $entity=e, $expire=t, $location=location);

	if ( ! hook NetControl::drop_rule_policy(r) )
		return "";

	local id = add_rule(r);


	if ( id == "" )
		return id;

	local log = DropInfo($ts=network_time(), $rule_id=id, $orig_h=a, $expire=t);

	if ( location != "" )
		log$location=location;

	Log::write(DROP_LOG, log);

	return id;
	}
