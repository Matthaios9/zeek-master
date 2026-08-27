





@load base/frameworks/broker
@load ./api

module SupervisorControl;

export {




	const topic_prefix = "zeek/supervisor" &redef;



	const enable_listen = F &redef;






	global SupervisorControl::create_request: event(reqid: string, node: Supervisor::NodeConfig);








	global SupervisorControl::create_response: event(reqid: string, result: string);







	global SupervisorControl::status_request: event(reqid: string, node: string);








	global SupervisorControl::status_response: event(reqid: string, result: Supervisor::Status);







	global SupervisorControl::restart_request: event(reqid: string, node: string);








	global SupervisorControl::restart_response: event(reqid: string, result: bool);







	global SupervisorControl::destroy_request: event(reqid: string, node: string);








	global SupervisorControl::destroy_response: event(reqid: string, result: bool);




	global SupervisorControl::stop_request: event();











	global SupervisorControl::node_status: event(node: string, pid: count);
}
