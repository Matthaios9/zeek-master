


@load ./main
@load base/frameworks/cluster

module Intel;



global insert_item: event(item: Item) &is_used;
global insert_indicator: event(item: Item) &is_used;


global new_min_data_store: event(store: MinDataStore) &is_used;




const send_store_on_node_up = T &redef;


@if ( Cluster::local_node_type() != Cluster::MANAGER )
redef have_full_data = F;
@endif

@if ( Cluster::local_node_type() == Cluster::MANAGER )

event remove_indicator(item: Item)
	{
	Cluster::publish(Cluster::worker_topic, remove_indicator, item);
	}


event Cluster::node_up(name: string, id: string)
	{



	if ( send_store_on_node_up && name in Cluster::nodes && Cluster::nodes[name]$node_type == Cluster::WORKER )
		{
		Cluster::publish(Cluster::node_topic(name), new_min_data_store, min_data_store);
		}
	}



event Intel::new_item(item: Item) &priority=5
	{



	local pt = Cluster::rr_topic(Cluster::proxy_pool, "intel_insert_rr_key");

	if ( pt == "" )


		pt = Cluster::worker_topic;

	Cluster::publish(pt, Intel::insert_indicator, item);
	}


event Intel::insert_item(item: Intel::Item) &priority=5
	{
	Intel::_insert(item, T);
	}


event Intel::remove_item(item: Item, purge_indicator: bool) &priority=5
	{
	remove(item, purge_indicator);
	}


event Intel::match_remote(s: Seen) &priority=5
	{
	if ( Intel::find(s) )
		event Intel::match(s, Intel::get_items(s));
	}
@endif


@if ( Cluster::local_node_type() == Cluster::WORKER )
event match_remote(s: Seen)
	{
	Cluster::publish(Cluster::manager_topic, match_remote, s);
	}

event remove_item(item: Item, purge_indicator: bool)
	{
	Cluster::publish(Cluster::manager_topic, remove_item, item, purge_indicator);
	}



event Intel::new_item(item: Intel::Item) &priority=5
	{
	Cluster::publish(Cluster::manager_topic, Intel::insert_item, item);
	}


event Intel::insert_indicator(item: Intel::Item) &priority=5
	{
	Intel::_insert(item, F);
	}

function invoke_indicator_hook(store: MinDataStore, h: hook(v: string, t: Intel::Type))
	{
	for ( a in store$host_data )
		hook h(cat(a), Intel::ADDR);

	for ( sn in store$subnet_data)
		hook h(cat(sn), Intel::SUBNET);

	for ( [indicator_value, indicator_type] in store$string_data )
		hook h(indicator_value, indicator_type);
	}






event new_min_data_store(store: MinDataStore)
	{
	invoke_indicator_hook(min_data_store, Intel::indicator_removed);

	min_data_store = store;

	invoke_indicator_hook(min_data_store, Intel::indicator_inserted);
	}
@endif

@if ( Cluster::local_node_type() == Cluster::PROXY )
event Intel::insert_indicator(item: Intel::Item) &priority=5
	{

	Cluster::publish(Cluster::worker_topic, Intel::insert_indicator, item);
	}
@endif
