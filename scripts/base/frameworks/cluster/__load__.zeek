
@load ./main
@load ./pools
@load ./publish-on-change
@load ./pubsub
@load ./telemetry
@load ./types

@if ( Cluster::is_enabled() )


redef peer_description = Cluster::node;

@if ( Cluster::enable_round_robin_logging )
redef Broker::log_topic = Cluster::rr_log_topic;
@endif


@prefixes += cluster

@if ( Supervisor::is_supervised() )



@load ./supervisor
@if ( Cluster::Supervisor::__init_cluster_nodes() && Cluster::get_node_count(Cluster::LOGGER) > 0 )
redef Cluster::manager_is_logger = F;
@endif
@endif

@if ( |Cluster::nodes| == 0 )




@load cluster-layout
@endif

@if ( Cluster::node in Cluster::nodes )

@load ./setup-subscriptions

@if ( Cluster::local_node_type() == Cluster::MANAGER )
@load ./nodes/manager

@if ( Cluster::manager_is_logger )
@load ./nodes/logger
@endif
@endif

@if ( Cluster::local_node_type() == Cluster::LOGGER )
@load ./nodes/logger
@endif

@if ( Cluster::local_node_type() == Cluster::PROXY )
@load ./nodes/proxy
@endif

@if ( Cluster::local_node_type() == Cluster::WORKER )
@load ./nodes/worker
@endif

@pragma push ignore-deprecations
@load ./broker-stores.zeek
@pragma pop ignore-deprecations

@endif
@endif
