

@load ./main
@load base/frameworks/cluster

module NetControl;

export {

	global cluster_netcontrol_add_rule: event(r: Rule);


	global cluster_netcontrol_remove_rule: event(id: string, reason: string);


	global cluster_netcontrol_delete_rule: event(id: string, reason: string);
}

function activate(p: PluginState, priority: int)
	{

	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return;

	activate_impl(p, priority);
	}

global local_rule_count: count = 1;

function add_rule(r: Rule) : string
	{
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return add_rule_impl(r);
	else
		{




		if ( [r$entity, r$ty] in rule_entities )
			{
			log_rule_no_plugin(r, FAILED, "discarded duplicate insertion");
			return "";
			}

		if ( r$id == "" )
			r$id = cat(Cluster::node, ":", ++local_rule_count);

		Cluster::publish(Cluster::manager_topic, NetControl::cluster_netcontrol_add_rule, r);
		return r$id;
		}
	}

function delete_rule(id: string, reason: string &default="") : bool
	{
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return delete_rule_impl(id, reason);
	else
		{
		Cluster::publish(Cluster::manager_topic, NetControl::cluster_netcontrol_delete_rule, id, reason);
		return T;
		}
	}

function remove_rule(id: string, reason: string &default="") : bool
	{
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return remove_rule_impl(id, reason);
	else
		{
		Cluster::publish(Cluster::manager_topic, NetControl::cluster_netcontrol_remove_rule, id, reason);
		return T;
		}
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event NetControl::cluster_netcontrol_delete_rule(id: string, reason: string)
	{
	delete_rule_impl(id, reason);
	}

event NetControl::cluster_netcontrol_add_rule(r: Rule)
	{
	add_rule_impl(r);
	}

event NetControl::cluster_netcontrol_remove_rule(id: string, reason: string)
	{
	remove_rule_impl(id, reason);
	}

event rule_expire(r: Rule, p: PluginState) &priority=-5
	{
	rule_expire_impl(r, p);
	}

event rule_exists(r: Rule, p: PluginState, msg: string) &priority=5
	{
	rule_added_impl(r, p, T, msg);

	if ( r?$expire && r$expire > 0secs && ! p$plugin$can_expire )
		schedule r$expire { rule_expire(r, p) };

	Cluster::publish(Cluster::worker_topic, rule_exists, r, p, msg);
	}

event rule_added(r: Rule, p: PluginState, msg: string) &priority=5
	{
	rule_added_impl(r, p, F, msg);

	if ( r?$expire && r$expire > 0secs && ! p$plugin$can_expire )
		schedule r$expire { rule_expire(r, p) };

	Cluster::publish(Cluster::worker_topic, rule_added, r, p, msg);
	}

event rule_removed(r: Rule, p: PluginState, msg: string) &priority=-5
	{
	rule_removed_impl(r, p, msg);

	Cluster::publish(Cluster::worker_topic, rule_removed, r, p, msg);
	}

event rule_timeout(r: Rule, i: FlowInfo, p: PluginState) &priority=-5
	{
	rule_timeout_impl(r, i, p);

	Cluster::publish(Cluster::worker_topic, rule_timeout, r, i, p);
	}

event rule_error(r: Rule, p: PluginState, msg: string) &priority=-5
	{
	rule_error_impl(r, p, msg);

	Cluster::publish(Cluster::worker_topic, rule_error, r, msg);
	}

event rule_new(r: Rule)
	{
	Cluster::publish(Cluster::worker_topic, rule_new, r);
	}

event rule_destroyed(r: Rule)
	{
	Cluster::publish(Cluster::worker_topic, rule_destroyed, r);
	}
@endif


@if ( Cluster::local_node_type() != Cluster::MANAGER )

event rule_new(r: Rule) &priority=5
	{
	if ( r$id in rules )
		return;

	rules[r$id] = r;
	rule_entities[r$entity, r$ty] = r;

	add_subnet_entry(r);
	}

event rule_destroyed(r: Rule) &priority=5
	{
	if ( r$id !in rules )
		return;

	remove_subnet_entry(r);
	if ( [r$entity, r$ty] in rule_entities )
		delete rule_entities[r$entity, r$ty];

	delete rules[r$id];
	}

@endif
