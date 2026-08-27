




@load policy/frameworks/management/types

module Management::Controller::API;

export {


	const version = 1;







	global get_instances_request: event(reqid: string);










	global get_instances_response: event(reqid: string,
	    result: Management::Result);














	global stage_configuration_request: event(reqid: string,
	    config: Management::Configuration);













	global stage_configuration_response: event(reqid: string,
	    results: Management::ResultVec);










	global get_configuration_request: event(reqid: string, deployed: bool);













	global get_configuration_response: event(reqid: string,
	    result: Management::Result);















	global deploy_request: event(reqid: string);












	global deploy_response: event(reqid: string,
	    results: Management::ResultVec);









	global get_nodes_request: event(reqid: string);
















	global get_nodes_response: event(reqid: string,
	    results: Management::ResultVec);

















	global get_id_value_request: event(reqid: string, id: string,
	    nodes: set[string] &default=set());














	global get_id_value_response: event(reqid: string, results: Management::ResultVec);















	global restart_request: event(reqid: string, nodes: set[string] &default=set());














	global restart_response: event(reqid: string, results: Management::ResultVec);















	global test_timeout_request: event(reqid: string, with_state: bool);








	global test_timeout_response: event(reqid: string,
	    result: Management::Result);












	global notify_agents_ready: event(instances: set[string]);
}
