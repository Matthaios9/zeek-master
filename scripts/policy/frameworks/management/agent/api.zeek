




@load base/frameworks/supervisor/control
@load policy/frameworks/management/types

module Management::Agent::API;

export {


	const version = 1;


















	global deploy_request: event(reqid: string,
	    config: Management::Configuration, force: bool &default=F);











	global deploy_response: event(reqid: string,
	    results: Management::ResultVec);









	global get_nodes_request: event(reqid: string);











	global get_nodes_response: event(reqid: string, result: Management::Result);



















	global node_dispatch_request: event(reqid: string, action: vector of string,
	    nodes: set[string] &default=set());














	global node_dispatch_response: event(reqid: string, results: Management::ResultVec);










	global agent_welcome_request: event(reqid: string);









	global agent_welcome_response: event(reqid: string,
	    result: Management::Result);












	global agent_standby_request: event(reqid: string);









	global agent_standby_response: event(reqid: string,
	    result: Management::Result);
















	global restart_request: event(reqid: string, nodes: set[string] &default=set());











	global restart_response: event(reqid: string, results: Management::ResultVec);



















	global notify_agent_hello: event(instance: string, id: string,
	    connecting: bool, api_version: count);





	global notify_change: event(instance: string,
	    n: Management::Node,
	    old: Management::State,
	    new: Management::State);


	global notify_error: event(instance: string, msg: string, node: string &default="");


	global notify_log: event(instance: string, msg: string, node: string &default="");
}
