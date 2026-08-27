

@load base/frameworks/cluster

module Cluster::Experimental;

export {




















	global node_fully_connected: event(name: string, id: string, resending: bool);














	global cluster_started: event();



	const cluster_started_topic = "zeek/cluster/experimental/started" &redef;
}






global connectees_pending: set[string];


global is_cluster_started = F;

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::MANAGER )
@load ./nodes-experimental/manager
@endif


hook Cluster::connect_node_hook(connectee: Cluster::NamedNode)
	{
	assert Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER;
	add connectees_pending[connectee$name];
	}

event zeek_init()
	{


	Cluster::subscribe(cluster_started_topic);
	}

event Cluster::node_up(name: string, id: string) &priority=-10
	{


	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		return;



	local mgr = Cluster::nodes[Cluster::node]?$manager ? Cluster::nodes[Cluster::node]$manager : "";
	if ( name !in connectees_pending && name != mgr )
		return;




	delete connectees_pending[name];
	if ( |connectees_pending| == 0 )
		{
		event node_fully_connected(Cluster::node, Cluster::node_id(), is_cluster_started);
		Cluster::publish(Cluster::manager_topic, node_fully_connected,
		                 Cluster::node, Cluster::node_id(), is_cluster_started);
		}
	}

event Cluster::Experimental::node_fully_connected(name: string, id: string, resending: bool)
	{
	if ( ! is_remote_event() )
		Cluster::log("fully connected");
	}

event Cluster::Experimental::cluster_started()
	{
	is_cluster_started = T;
	}






















event zeek_init()
	{


	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER )
		return;


	for ( name, _ in Cluster::nodes )
		if ( name != Cluster::node )
			add connectees_pending[name];
	}

event Cluster::node_up(name: string, id: string)
	{


	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER )
		return;

	delete connectees_pending[name];

	if ( |connectees_pending| == 0 )
		{
		event node_fully_connected(Cluster::node, Cluster::node_id(), is_cluster_started);

		Cluster::publish(Cluster::manager_topic,
		                 Cluster::Experimental::node_fully_connected,
		                 Cluster::node,
		                 Cluster::node_id(),
		                 is_cluster_started);
		}
	}
@endif
