



module Control;

export {

	const topic_prefix = "zeek/control";



	const controllee_listen = T &redef;


	const host = 0.0.0.0 &redef;


	const host_port = 0/tcp &redef;



	const zone_id = "" &redef;



	const cmd = "" &redef;


	const arg = "" &redef;



	const commands: set[string] = {
		"id_value",
		"peer_status",
		"net_stats",
		"configuration_update",
		"shutdown",
	} &redef;


	const ignore_ids: set[string] = { };


	global id_value_request: event(id: string);


	global id_value_response: event(id: string, val: string);


	global peer_status_request: event();

	global peer_status_response: event(s: string);


	global net_stats_request: event();

	global net_stats_response: event(s: string);



	global configuration_update_request: event();



	global configuration_update: event();

	global configuration_update_response: event();


	global shutdown_request: event();

	global shutdown_response: event();
}

event terminate_event() &is_used
	{
	terminate();
	}
