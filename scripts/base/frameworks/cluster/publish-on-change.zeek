

module Cluster;

export {



	const default_publish_table_batch_size = 10000 &redef;









	global publish_table: function(
		topic: string,
		table_val: any,
		batch_size: count &default=default_publish_table_batch_size
	): bool;

}

@load base/bif/publish_on_change.bif

function publish_table(topic: string, table_val: any, batch_size: count): bool
	{
	return __publish_table(topic, table_val, batch_size);
	}






event table_change_infos(tcheader: TableChangeHeader, tcinfos: TableChangeInfos)
	{



	if ( tcheader$node_id == Cluster::node_id() )
		{
		if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
			Reporter::warning("Got table_change_infos() event from self");

		return;
		}




	if ( ! hook apply_table_change_infos_policy(tcheader, tcinfos) )
		return;

	apply_table_change_infos(tcheader, tcinfos);
	}




global topic_prefixes: table[pattern] of string;

hook Cluster::on_subscribe(topic: string)
	{

	local pat = string_to_pattern(convert_for_pattern(topic) + ".*", F);
	topic_prefixes[pat] = topic;
	}









event forward_table_change_infos(tcheader: TableChangeHeader, tcinfos: TableChangeInfos, to_topic: string)
	{
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		Reporter::fatal(fmt("forward_table_change_infos unexpected for %s", Cluster::backend));

	if ( Cluster::local_node_type() != Cluster::MANAGER )
		Reporter::fatal(fmt("%s got unexpected event forward_table_change_infos to=%s id=%s)",
		                    Cluster::node, to_topic, tcheader$id));


	Cluster::publish(to_topic, table_change_infos, tcheader, tcinfos);






	if ( to_topic in topic_prefixes )
		event table_change_infos(tcheader, tcinfos);
	}

event zeek_init()
	{



	local topic_separator = "/";
	local topic = join_string_vec(vector("zeek", "table", ""), topic_separator);
	Cluster::subscribe(topic);


	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER && Cluster::local_node_type() == Cluster::WORKER )
		set_table_change_infos_forward_topic(Cluster::manager_topic);
	}
