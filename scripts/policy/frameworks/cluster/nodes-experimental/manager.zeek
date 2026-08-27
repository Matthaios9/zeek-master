


@load base/frameworks/cluster
@load policy/frameworks/cluster/experimental

module Cluster::Experimental;

global fully_connected_nodes_pending: set[string];

event zeek_init()
	{
	fully_connected_nodes_pending = table_keys(Cluster::nodes);
	}

event node_fully_connected(name: string, id: string, resending: bool)
	{



	is_cluster_started = is_cluster_started || resending;

	delete fully_connected_nodes_pending[name];
	if ( !is_cluster_started && |fully_connected_nodes_pending| == 0 )
		{
		event cluster_started();

		Cluster::publish(cluster_started_topic,
		                 Cluster::Experimental::cluster_started);
		}
	}

event cluster_started()
	{
	Cluster::log("cluster connected");
	}



event zeek_init() &priority=-15
	{






	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		return;

	if ( |connectees_pending| == 0 )
		event node_fully_connected(Cluster::node, Cluster::node_id(), F);
	}

event Cluster::node_up(name: string, id: string)
	{







	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		return;

	local n = Cluster::nodes[name];
	if ( n$node_type == Cluster::LOGGER && ! n?$manager )
		event node_fully_connected(name, id, F);
	}
