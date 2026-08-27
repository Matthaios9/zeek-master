


























































































































module Cluster::Backend::ZeroMQ;

export {




	const connect_xpub_endpoint = "tcp://127.0.0.1:5556" &redef;






	const connect_xsub_endpoint = "tcp://127.0.0.1:5555" &redef;





	const connect_log_endpoints: vector of string &redef;










	const run_proxy_thread: bool = F &redef;







	const proxy_io_threads = 2 &redef;





	const listen_xsub_endpoint = "tcp://127.0.0.1:5556" &redef;





	const listen_xpub_endpoint = "tcp://127.0.0.1:5555" &redef;





	const listen_log_endpoint = "" &redef;












	const linger_ms: int = 500 &redef;








	const xpub_sndhwm: int = 1000 &redef;







	const xpub_sndbuf: int = -1 &redef;








	const xsub_rcvhwm: int = 1000 &redef;







	const xsub_rcvbuf: int = -1 &redef;












	const onloop_queue_hwm = 10000 &redef;









	const log_immediate: bool = F &redef;









	const log_sndhwm: int = 1000 &redef;









	const log_rcvhwm: int = 1000 &redef;






	const log_sndbuf: int = -1 &redef;







	const log_rcvbuf: int = -1 &redef;











	const ipv6 = F &redef;












	const connect_xpub_nodrop: bool = T &redef;












	const listen_xpub_nodrop: bool = T &redef;





	const poll_max_messages = 100 &redef;










	const debug_flags: count = 0 &redef;







	const curve_server_publickey = "" &redef;



	const curve_server_secretkey = "" &redef;



	const curve_client_publickey = "" &redef;



	const curve_client_secretkey = "" &redef;


	global node_topic_prefix = "zeek.cluster.node" &redef;


	global nodeid_topic_prefix = "zeek.cluster.nodeid" &redef;









	global subscription: event(topic: string);









	global unsubscription: event(topic: string);









	global monitoring_event: event(number: count, value: count, address: string);






	global hello: event(name: string, id: string);






	const hello_expiration: interval = 10sec &redef;











	const internal_topic_prefix = "zeek.zeromq.internal." &redef;
}

@load base/utils/addrs


redef Cluster::backend = Cluster::CLUSTER_BACKEND_ZEROMQ;


redef run_proxy_thread = Cluster::local_node_type() == Cluster::MANAGER;


function zeromq_node_topic(name: string): string {
	return node_topic_prefix + "." + name + ".";
}

function zeromq_nodeid_topic(id: string): string {
	return nodeid_topic_prefix + "." + id + ".";
}

redef Cluster::Telemetry::topic_normalizations += {
	[/^zeek\.cluster\.nodeid\..*/] = "zeek.cluster.nodeid.__normalized__",
};


const my_node_id = fmt("zeromq_%s_%s_%s_%s",  Cluster::node, gethostname(), getpid(), unique_id("N"));

function zeromq_node_id(): string {
	return my_node_id;
}

redef Cluster::node_topic = zeromq_node_topic;
redef Cluster::nodeid_topic = zeromq_nodeid_topic;
redef Cluster::node_id = zeromq_node_id;

redef Cluster::logger_topic = "zeek.cluster.logger";
redef Cluster::manager_topic = "zeek.cluster.manager";
redef Cluster::proxy_topic = "zeek.cluster.proxy";
redef Cluster::worker_topic = "zeek.cluster.worker";

redef Cluster::proxy_pool_spec = Cluster::PoolSpec(
	$topic = "zeek.cluster.pool.proxy",
	$node_type = Cluster::PROXY);

redef Cluster::logger_pool_spec = Cluster::PoolSpec(
	$topic = "zeek.cluster.pool.logger",
	$node_type = Cluster::LOGGER);

redef Cluster::worker_pool_spec = Cluster::PoolSpec(
	$topic = "zeek.cluster.pool.worker",
	$node_type = Cluster::WORKER);



@if ( Cluster::local_node_type() == Cluster::LOGGER || (Cluster::manager_is_logger && Cluster::local_node_type() == Cluster::MANAGER) )
const my_node = Cluster::nodes[Cluster::node];
@if ( my_node?$p )
redef listen_log_endpoint = fmt("tcp://%s:%s", addr_to_uri(my_node$ip), port_to_count(my_node$p));
@endif
@endif
