@load policy/frameworks/management/types

module Management::Supervisor::API;

export {











	global notify_node_exit: event(node: string, outputs: Management::NodeOutputs);
}
