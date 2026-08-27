







@deprecated "Remove in v9.1. Broker stores have been deprecated. To distribute state across cluster nodes, use the new &publish_on_change attribute for global sets/tables, or leverage explicit remote events with Cluster::publish(). For state persistence, use the storage framework.";

@load ./main

module Broker;

export {


	global announce_masters: event(masters: set[string]);
}



@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
redef Broker::table_store_master = F;
@endif

@if ( Broker::table_store_master )

global broker_backed_ids: set[string];

event zeek_init()
	{
	local globals = global_ids();
	for ( id in globals )
		{
		if ( globals[id]$broker_backend )
			add broker_backed_ids[id];
		}
	}






event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) &priority=11
	{
	if ( ! Cluster::is_enabled() )
		return;

	local e = Broker::make_event(Broker::announce_masters, broker_backed_ids);
	Broker::publish(Cluster::nodeid_topic(endpoint$id), e);
	}

@else

event Broker::announce_masters(masters: set[string])
	{
	for ( i in masters )
		{

		local name = "___sync_store_" + i;
@pragma push ignore-deprecations
		Broker::create_clone(name);
@pragma pop ignore-deprecations
		}
	}

@endif
