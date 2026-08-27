
















@load base/frameworks/control
@load base/frameworks/broker

@load ./types

module Cluster;

export {

	const enable_round_robin_logging = T &redef;



	const logger_topic = "zeek/cluster/logger" &redef;



	const manager_topic = "zeek/cluster/manager" &redef;



	const proxy_topic = "zeek/cluster/proxy" &redef;



	const worker_topic = "zeek/cluster/worker" &redef;





	const broadcast_topics = {
		logger_topic,
		manager_topic,
		proxy_topic,
		worker_topic,
	};



	const node_topic_prefix = "zeek/cluster/node/" &redef;



	const nodeid_topic_prefix = "zeek/cluster/nodeid/" &redef;





	const default_master_node = "" &redef;



	const default_backend = Broker::MEMORY &redef;





	const default_persistent_backend = Broker::SQLITE &redef;





	const default_store_dir = "" &redef;


	type StoreInfo: record {

		name: string &optional;

		store: opaque of Broker::Store &optional;


		master_node: string &default=default_master_node;

		master: bool &default=F;

		backend: Broker::BackendType &default=default_backend;

		options: Broker::BackendOptions &default=Broker::BackendOptions();


		clone_resync_interval: interval &default=Broker::default_clone_resync_interval;


		clone_stale_interval: interval &default=Broker::default_clone_stale_interval;


		clone_mutation_buffer_interval: interval &default=Broker::default_clone_mutation_buffer_interval;
	};








	global stores: table[string] of StoreInfo &default=StoreInfo() &redef;











	global create_store: function(name: string, persistent: bool &default=F): StoreInfo
	&deprecated="Remove in v9.1. Cluster::create_store() uses Broker stores which are deprecated. To distribute state across cluster nodes, use the new &publish_on_change attribute for global sets/tables, or leverage explicit remote events with Cluster::publish(). For state persistence, use the storage framework.";


	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;


	type Info: record {

		ts:       time;

		node: string;

		message:  string;
	} &log;





	global is_enabled: function(): bool;







	global local_node_type: function(): NodeType;







	global local_node_metrics_port: function(): port;







	const nodes: table[string] of Node = {} &redef;



	global get_node_count: function(node_type: NodeType): count;




	global get_active_node_count: function(node_type: NodeType): count;





	const manager_is_logger = T &redef;



	const node = getenv("CLUSTER_NODE") &redef;






	global node_id: function(): string = Broker::node_id &redef;




	const retry_interval = 1sec &redef;





	global hello: event(name: string, id: string);



	global node_up: event(name: string, id: string);



	global node_down: event(name: string, id: string);


	global log: function(msg: string);







	global node_topic: function(name: string): string &redef;








	global nodeid_topic: function(id: string): string &redef;








	global nodeid_to_node: function(id: string): NamedNode;






	global init: function(): bool;






	global listen_websocket: function(options: WebSocketServerOptions): bool;








	global connect_node_hook: hook(connectee: NamedNode);
}

@load base/bif/cluster.bif
@load base/bif/plugins/Zeek_Cluster_WebSocket.events.bif.zeek


global active_node_ids: table[NodeType] of set[string];

function nodes_with_type(node_type: NodeType): vector of NamedNode
	{
	local rval: vector of NamedNode = vector();

	for ( name, n in Cluster::nodes )
		{
		if ( n$node_type != node_type )
			next;

		rval += NamedNode($name=name, $node=n);
		}

	return sort(rval, function(n1: NamedNode, n2: NamedNode): int
		{ return strcmp(n1$name, n2$name); });
	}

function get_node_count(node_type: NodeType): count
	{
	local cnt = 0;

	for ( _, n in nodes )
		{
		if ( n$node_type == node_type )
			++cnt;
		}

	return cnt;
	}

function get_active_node_count(node_type: NodeType): count
	{
	return node_type in active_node_ids ? |active_node_ids[node_type]| : 0;
	}

function is_enabled(): bool
	{
	return (node != "");
	}

function local_node_type(): NodeType
	{
	if ( ! is_enabled() )
		return NONE;

	if ( node !in nodes )
		return NONE;

	return nodes[node]$node_type;
	}

function local_node_metrics_port(): port
	{
	if ( ! is_enabled() )
		return 0/unknown;

	if ( node !in nodes )
		return 0/unknown;

	if ( ! nodes[node]?$metrics_port )
		return 0/unknown;

	return nodes[node]$metrics_port;
	}

function node_topic(name: string): string
	{
	return node_topic_prefix + name + "/";
	}

function nodeid_topic(id: string): string
	{
	return nodeid_topic_prefix + id + "/";
	}

function nodeid_to_node(id: string): NamedNode
	{
	for ( name, n in nodes )
		{
		if ( n?$id && n$id == id )
			return NamedNode($name=name, $node=n);
		}

	return NamedNode($name="", $node=Node($node_type=NONE, $ip=0.0.0.0));
	}

event Cluster::hello(name: string, id: string) &priority=10
	{
	if ( name !in nodes )
		{
		Reporter::error(fmt("Got Cluster::hello msg from unexpected node: %s", name));
		return;
		}

	local n = nodes[name];

	if ( n?$id )
		{
		if ( n$id != id )
			Reporter::error(fmt("Got Cluster::hello msg from duplicate node:%s",
								name));
		}
	else
		event Cluster::node_up(name, id);

	n$id = id;
	Cluster::log(fmt("got hello from %s (%s)", name, id));

	if ( n$node_type !in active_node_ids )
		active_node_ids[n$node_type] = set();
	add active_node_ids[n$node_type][id];
	}

event node_down(name: string, id: string) &priority=10
	{
	local found = F;
	for ( node_name, n in nodes )
		{
		if ( n?$id && n$id == id )
			{
			Cluster::log(fmt("node down: %s", node_name));
			delete n$id;
			delete active_node_ids[n$node_type][id];
			found = T;
			break;
			}
		}

	if ( ! found )
		Reporter::error(fmt("No node found in Cluster::node_down() node:%s id:%s",
		                    name, id));
	}

event zeek_init() &priority=5
	{

	if ( node != "" && node !in nodes )
		{
		Reporter::error(fmt("'%s' is not a valid node in the Cluster::nodes configuration", node));
		terminate();
		}

	if ( node != "" && Cluster::backend == Cluster::CLUSTER_BACKEND_NONE )
		Reporter::fatal(fmt("Cluster::node set to '%s', but Cluster::backend is %s - please select a cluster backend to use.", Cluster::node, Cluster::backend));

	Log::create_stream(Cluster::LOG, Log::Stream($columns=Info, $path="cluster", $policy=log_policy));
	}

function create_store(name: string, persistent: bool &default=F): Cluster::StoreInfo
	{
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER && Cluster::backend != Cluster::CLUSTER_BACKEND_NONE )
		Reporter::fatal(fmt("Call to Cluster::create_store() with non-Broker backend %s selected", Cluster::backend));

	local info = stores[name];
	info$name = name;

	if ( Cluster::default_store_dir != "" )
		{
		local default_options = Broker::BackendOptions();
		local path = Cluster::default_store_dir + "/" + name;

		if ( info$options$sqlite$path == default_options$sqlite$path )
			info$options$sqlite$path = path + ".sqlite";
		}

	if ( persistent )
		{
		switch ( info$backend ) {
		case Broker::MEMORY:
			info$backend = Cluster::default_persistent_backend;
			break;
		case Broker::SQLITE:

			break;
		default:
			Reporter::error(fmt("unhandled data store type: %s", info$backend));
			break;
		}
		}

	if ( ! Cluster::is_enabled() )
		{
		if ( info?$store )
			{
			Reporter::warning(fmt("duplicate cluster store creation for %s", name));
			return info;
			}

@pragma push ignore-deprecations
		info$store = Broker::create_master(name, info$backend, info$options);
@pragma pop ignore-deprecations
		info$master = T;
		stores[name] = info;
		return info;
		}

	if ( info$master_node == "" )
		{
		local mgr_nodes = nodes_with_type(Cluster::MANAGER);

		if ( |mgr_nodes| == 0 )
			Reporter::fatal(fmt("empty master node name for cluster store " +
								"'%s', but there's no manager node to default",
			                    name));

		info$master_node = mgr_nodes[0]$name;
		}
	else if ( info$master_node !in Cluster::nodes )
		Reporter::fatal(fmt("master node '%s' for cluster store '%s' does not exist",
		                    info$master_node, name));

@pragma push ignore-deprecations
	if ( Cluster::node == info$master_node )
		{
		info$store = Broker::create_master(name, info$backend, info$options);
		info$master = T;
		stores[name] = info;
		Cluster::log(fmt("created master store: %s", name));
		return info;
		}

	info$master = F;
	stores[name] = info;
	info$store = Broker::create_clone(info$name,
	                                  info$clone_resync_interval,
	                                  info$clone_stale_interval,
	                                  info$clone_mutation_buffer_interval);
@pragma pop ignore-deprecations
	Cluster::log(fmt("created clone store: %s", info$name));
	return info;
	}

function log(msg: string)
	{
	Log::write(Cluster::LOG, Info($ts = network_time(), $node = node, $message = msg));
	}

function init(): bool
	{
	return Cluster::Backend::__init(Cluster::node_id());
	}

function listen_websocket(options: WebSocketServerOptions): bool
	{
	return Cluster::__listen_websocket(options);
	}

function format_endpoint_info(ei: EndpointInfo): string
	{
	local s = fmt("'%s' (%s:%d)", ei$id, ei$network$address, ei$network$bound_port);
	if ( ei?$application_name )
		s += fmt(" application_name=%s", ei$application_name);
	return s;
	}

event websocket_client_added(endpoint: EndpointInfo, subscriptions: string_vec)
	{
	local msg = fmt("WebSocket client %s subscribed to %s",
	                format_endpoint_info(endpoint), subscriptions);
	Cluster::log(msg);
	}

event websocket_client_lost(endpoint: EndpointInfo, code: count, reason: string)
	{
	local msg = fmt("WebSocket client %s gone with code %d%s",
	                format_endpoint_info(endpoint), code,
	                |reason| > 0 ? fmt(" and reason '%s'", reason) : "");
	Cluster::log(msg);
	}


event Cluster::Backend::error(tag: string, message: string)
	{
	local msg = fmt("Cluster::Backend::error: %s (%s)", tag, message);
	Reporter::error(msg);
	}
