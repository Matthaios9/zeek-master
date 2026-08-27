

@load ./main
@load base/frameworks/cluster

module OpenFlow;

export {

	global cluster_flow_mod: event(name: string, match: ofp_match, flow_mod: ofp_flow_mod);


	global cluster_flow_clear: event(name: string);
}


function flow_mod(controller: Controller, match: ofp_match, flow_mod: ofp_flow_mod): bool
	{
	if ( ! controller?$flow_mod )
		return F;

	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return controller$flow_mod(controller$state, match, flow_mod);
	else
		Cluster::publish(Cluster::manager_topic, OpenFlow::cluster_flow_mod, controller$state$_name, match, flow_mod);

	return T;
	}

function flow_clear(controller: Controller): bool
	{
	if ( ! controller?$flow_clear )
		return F;

	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return controller$flow_clear(controller$state);
	else
		Cluster::publish(Cluster::manager_topic, OpenFlow::cluster_flow_clear, controller$state$_name);

	return T;
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event OpenFlow::cluster_flow_mod(name: string, match: ofp_match, flow_mod: ofp_flow_mod)
	{
	if ( name !in name_to_controller )
		{
		Reporter::error(fmt("OpenFlow controller %s not found in mapping on master", name));
		return;
		}

	local c = name_to_controller[name];

	if ( ! c$state$_activated )
		return;

	if ( c?$flow_mod )
		c$flow_mod(c$state, match, flow_mod);
	}

event OpenFlow::cluster_flow_clear(name: string)
	{
	if ( name !in name_to_controller )
		{
		Reporter::error(fmt("OpenFlow controller %s not found in mapping on master", name));
		return;
		}

	local c = name_to_controller[name];

	if ( ! c$state$_activated )
		return;

	if ( c?$flow_clear )
		c$flow_clear(c$state);
	}
@endif

function register_controller(tpe: OpenFlow::Plugin, name: string, controller: Controller)
	{
	controller$state$_name = cat(tpe, name);
	controller$state$_plugin = tpe;


	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return;

	register_controller_impl(tpe, name, controller);
	}

function unregister_controller(controller: Controller)
	{

	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return;

	unregister_controller_impl(controller);
	}

function lookup_controller(name: string): vector of Controller
	{

	if ( Cluster::local_node_type() != Cluster::MANAGER )
		return vector();











	return lookup_controller_impl(name);
	}
