



@load policy/frameworks/management/types

module Management::Node::API;

export {












	global node_dispatch_request: event(reqid: string, action: vector of string,
	    nodes: set[string] &default=set());










	global node_dispatch_response: event(reqid: string, result: Management::Result);












	global notify_node_hello: event(node: string);
}
