





















module Cluster;

redef Cluster::backend = Cluster::CLUSTER_BACKEND_BROKER;

function connect_peer(node_type: NodeType, node_name: string)
	{
	local nn = nodes_with_type(node_type);

	for ( i in nn )
		{
		local n = nn[i];

		if ( n$name != node_name )
			next;
		if ( ! hook connect_node_hook(n) )
			return;

		local status = Broker::peer(cat(n$node$ip), n$node$p,
		                            Cluster::retry_interval);
		Cluster::log(fmt("initiate peering with %s:%s, retry=%s, status=%s",
		                 n$node$ip, n$node$p, Cluster::retry_interval,
		                 status));
		return;
		}

	Reporter::warning(fmt("connect_peer: node '%s' (%s) not found", node_name, node_type));
	}

function connect_peers_with_type(node_type: NodeType)
	{
	local nn = nodes_with_type(node_type);

	for ( i in nn )
		{
		local n = nn[i];

		if ( ! hook connect_node_hook(n) )
			next;

		local status = Broker::peer(cat(n$node$ip), n$node$p,
		                            Cluster::retry_interval);
		Cluster::log(fmt("initiate peering with %s:%s, retry=%s, status=%s",
		                 n$node$ip, n$node$p, Cluster::retry_interval,
		                 status));
		}
	}




event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) &priority=10
	{
	if ( ! Cluster::is_enabled() )
		return;

	local e = Broker::make_event(Cluster::hello, node, Cluster::node_id());
	Broker::publish(nodeid_topic(endpoint$id), e);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string) &priority=10
	{
	for ( node_name, n in nodes )
		{
		if ( n?$id && n$id == endpoint$id )
			{
			event Cluster::node_down(node_name, endpoint$id);
			break;
			}
		}
	}




event zeek_init() &priority=-10
	{
	if ( getenv("ZEEKCTL_CHECK_CONFIG") != "" )
		return;

	if ( ! Cluster::is_enabled() )
		return;

	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		return;

	local self = Cluster::nodes[Cluster::node];



	switch ( self$node_type ) {
	case LOGGER:
		Cluster::subscribe(Broker::default_log_topic_prefix);
		break;
	case MANAGER:
		if ( Cluster::manager_is_logger )
			Cluster::subscribe(Broker::default_log_topic_prefix);
		break;
	}

	if ( self$p != 0/unknown )
		{
		Broker::listen(Broker::default_listen_address,
		               self$p,
		               Broker::default_listen_retry);

		Cluster::log(fmt("listening on %s:%s", Broker::default_listen_address, self$p));
		}


	switch ( self$node_type ) {
	case MANAGER:
		connect_peers_with_type(LOGGER);

		break;
	case PROXY:
		connect_peers_with_type(LOGGER);

		if ( self?$manager )
			connect_peer(MANAGER, self$manager);

		break;
	case WORKER:
		connect_peers_with_type(LOGGER);
		connect_peers_with_type(PROXY);

		if ( self?$manager )
			connect_peer(MANAGER, self$manager);

		break;
	}
	}
