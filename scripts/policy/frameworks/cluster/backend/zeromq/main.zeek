

module Cluster::Backend::ZeroMQ;

@load ./options
@load base/utils/addrs




event zeek_init() &priority=100
	{
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_ZEROMQ )
		return;

	if ( Cluster::local_node_type() == Cluster::LOGGER )
		return;

	if ( Cluster::manager_is_logger && Cluster::local_node_type() == Cluster::MANAGER )
		return;

	for ( _, node in Cluster::nodes )
		{
		local endp: string;
		if ( node$node_type == Cluster::LOGGER && node?$p )
			{
			endp = fmt("tcp://%s:%s", addr_to_uri(node$ip), node$p as count);
			connect_log_endpoints += endp;
			}

		if ( Cluster::manager_is_logger && node$node_type == Cluster::MANAGER && node?$p )
			{
			endp = fmt("tcp://%s:%s", node$ip, node$p as count);
			connect_log_endpoints += endp;
			}
		}




	if ( |connect_log_endpoints| == 0 && |Cluster::nodes| > 1 )
		Reporter::error("No ZeroMQ connect_log_endpoints configured");
	}

event zeek_init() &priority=10
	{
	if ( getenv("ZEEKCTL_CHECK_CONFIG") != "" )
		return;


	if ( getenv("ZEEKCTL_DISABLE_LISTEN") != "" )
		return;

	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_ZEROMQ )
		return;

	if ( run_proxy_thread )
		{
		if ( ! Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread() )
			Reporter::fatal("Failed to spawn ZeroMQ proxy thread");
		}

	if ( ! Cluster::init() )
		Reporter::fatal("Failed initialize ZeroMQ backend");
	}

function nodeid_subscription_expired(nodeids: set[string], nodeid: string): interval
	{
	Reporter::warning(fmt("Expired subscription from nodeid %s", nodeid));
	return 0.0sec;
	}

function nodeid_hello_expired(nodeids: set[string], nodeid: string): interval
	{
	Reporter::warning(fmt("Expired hello from nodeid %s", nodeid));
	return 0.0sec;
	}


global nodeid_subscriptions: set[string] &create_expire=hello_expiration &expire_func=nodeid_subscription_expired;
global nodeid_hellos: set[string] &create_expire=hello_expiration &expire_func=nodeid_hello_expired;



















event Cluster::Backend::ZeroMQ::subscription(topic: string)
	{
	local prefix = nodeid_topic_prefix + ".";

	if ( ! starts_with(topic, prefix) )
		return;

	local nodeid = topic[|prefix|:][:-1];


	if ( nodeid  == Cluster::node_id() )
		return;

	Cluster::publish(topic, Cluster::Backend::ZeroMQ::hello, Cluster::node, Cluster::node_id());



	if ( nodeid in nodeid_hellos )
		{
		Cluster::publish(Cluster::nodeid_topic(nodeid), Cluster::hello, Cluster::node, Cluster::node_id());
		delete nodeid_hellos[nodeid];
		}
	else
		{
		add nodeid_subscriptions[nodeid];
		}
	}




event Cluster::Backend::ZeroMQ::hello(name: string, id: string)
	{
	if ( name in Cluster::nodes )
		{
		local n = Cluster::nodes[name];
		if ( n?$id )
			{
			if ( n$id == id )
				{

				Reporter::warning(fmt("node '%s' sends ZeroMQ::hello twice (id:%s)",
						  name, id));
				return;
				}

			Reporter::warning(fmt("node '%s' never said goodbye (old id:%s new id:%s",
			                      name, n$id, id));



			event Cluster::node_down(name, n$id);
			}
		}





	if ( id in nodeid_subscriptions )
		{
		Cluster::publish(Cluster::nodeid_topic(id), Cluster::hello, Cluster::node, Cluster::node_id());
		delete nodeid_subscriptions[id];
		}
	else
		{
		add nodeid_hellos[id];
		}
	}




event Cluster::Backend::ZeroMQ::unsubscription(topic: string)
	{
	local prefix = nodeid_topic_prefix + ".";
	if ( ! starts_with(topic, prefix) )
		return;

	local gone_node_id = topic[|prefix|:][:-1];
	local name = "";
	for ( node_name, n in Cluster::nodes ) {
		if ( n?$id && n$id == gone_node_id ) {
			name = node_name;
			break;
		}
	}

	if ( name != "" )
		event Cluster::node_down(name, gone_node_id);
	else
		Reporter::warning(fmt("unsubscription of unknown node with id '%s'", gone_node_id));
	}

event Cluster::Backend::ZeroMQ::monitoring_event(number: count, value: count, address: string)
	{



















	if ( number == 0x0800 )
		Reporter::warning(fmt("ZeroMQ: Handshake for socket %s failed: event=0x%x value=%s", address, number, value));

	if ( number == 0x2000 || number == 0x4000 )
		Reporter::fatal(fmt("ZeroMQ: Handshake for socket %s failed: event=0x%x value=%s", address, number, value));
	}
