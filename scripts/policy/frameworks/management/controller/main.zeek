




@load base/frameworks/broker
@load base/frameworks/cluster

@load policy/frameworks/management
@load policy/frameworks/management/agent/config
@load policy/frameworks/management/agent/api

@load ./api
@load ./config

module Management::Controller::Runtime;




export {


	type ConfigState: enum {
		STAGED,
		READY,
		DEPLOYED,
	};




	type DeployState: record {

		config: Management::Configuration;


		is_internal: bool &default=F;

		requests: set[string] &default=set();
	};




	type GetNodesState: record {

		requests: set[string] &default=set();
	};












	type NodeDispatchState: record {


		action: vector of string;





		requests: set[string] &default=set();
	};




	type RestartState: record {

		requests: set[string] &default=set();
	};


	type TestState: record { };
}

redef record Management::Request::Request += {
	deploy_state: DeployState &optional;
	get_nodes_state: GetNodesState &optional;
	node_dispatch_state: NodeDispatchState &optional;
	restart_state: RestartState &optional;
	test_state: TestState &optional;
};


redef Management::role = Management::CONTROLLER;



redef table_expire_interval = 2 sec;




global check_instances_ready: function();


global add_instance: function(inst: Management::Instance);



global drop_instance: function(inst: Management::Instance);




global config_deploy_to_agents: function(config: Management::Configuration,
    req: Management::Request::Request);



global config_nodes_lacking_broker_ports: function(config: Management::Configuration): vector of string;






global config_assign_broker_ports: function(config: Management::Configuration);


global config_assign_metrics_ports: function(config: Management::Configuration);





global config_validate: function(config: Management::Configuration,
    req: Management::Request::Request): bool;



global config_filter_nodes_by_name: function(config: Management::Configuration,
    nodes: set[string]): set[string];



global find_endpoint: function(id: string): Broker::EndpointInfo;





global is_instance_connectivity_change: function(inst: Management::Instance): bool;





global g_instances: table[string] of Management::Instance = table();




global g_instances_known: table[string] of Management::Instance = table();







global g_instances_ready: set[string] = set();




global g_instances_by_id: table[string] of string;




global g_config_reqid_pending: string = "";


global g_configs: table[ConfigState] of Management::Configuration
    &broker_allow_complex_type &backend=Broker::SQLITE;

function config_deploy_to_agents(config: Management::Configuration, req: Management::Request::Request)
	{
	for ( name in g_instances )
		{
		if ( name !in g_instances_ready )
			next;

		local agent_topic = Management::Agent::topic_prefix + "/" + name;
		local areq = Management::Request::create();
		areq$parent_id = req$id;




		add req$deploy_state$requests[areq$id];



		Management::Log::info(fmt("tx Management::Agent::API::deploy_request %s to %s", areq$id, name));
		Broker::publish(agent_topic, Management::Agent::API::deploy_request, areq$id, config, F);
		}
	}

function check_instances_ready()
	{
	local cur_instances: set[string];

	for ( inst in g_instances )
		add cur_instances[inst];

	if ( cur_instances == g_instances_ready )
		event Management::Controller::API::notify_agents_ready(cur_instances);
	}

function add_instance(inst: Management::Instance)
	{
	g_instances[inst$name] = inst;

	if ( inst?$listen_port )
		Broker::peer(cat(inst$host), inst$listen_port,
		    Management::connect_retry);

	if ( inst$name in g_instances_known )
		{



		if ( ! inst?$listen_port )
			inst$host = g_instances_known[inst$name]$host;





		local req = Management::Request::create();

		Management::Log::info(fmt("tx Management::Agent::API::agent_welcome_request %s to %s", req$id, inst$name));
		Broker::publish(Management::Agent::topic_prefix + "/" + inst$name,
		    Management::Agent::API::agent_welcome_request, req$id);
		}
	else
		Management::Log::debug(fmt("instance %s not known to us, skipping", inst$name));
	}

function drop_instance(inst: Management::Instance)
	{
	if ( inst$name !in g_instances )
		return;


	Management::Log::info(fmt("tx Management::Agent::API::agent_standby_request to %s", inst$name));
	Broker::publish(Management::Agent::topic_prefix + "/" + inst$name,
	    Management::Agent::API::agent_standby_request, "");

	delete g_instances[inst$name];

	if ( inst$name in g_instances_ready )
		delete g_instances_ready[inst$name];




	Management::Log::info(fmt("dropped instance %s", inst$name));
	}

function config_nodes_lacking_broker_ports(config: Management::Configuration): vector of string
	{
	local res: vector of string;
	local roles = { Supervisor::MANAGER, Supervisor::LOGGER, Supervisor::PROXY };

	for ( node in config$nodes )
		{
		if ( node$role in roles && ! node?$p )
			res += node$name;
		}

	return sort(res, strcmp);
	}





function config_nodes_compare(n1: Management::Node, n2: Management::Node, roles: table[Supervisor::ClusterRole] of count): int
	{
	local instcmp = strcmp(n1$instance, n2$instance);
	if ( instcmp != 0 )
		return instcmp;
	if ( roles[n1$role] < roles[n2$role] )
		return -1;
	if ( roles[n1$role] > roles[n2$role] )
		return 1;
	return strcmp(n1$name, n2$name);
	}

function config_assign_broker_ports(config: Management::Configuration)
	{

	local new_nodes: set[Management::Node];


	local roles: table[Supervisor::ClusterRole] of count = {
		[Supervisor::MANAGER] = 0,
		[Supervisor::LOGGER] = 1,
		[Supervisor::PROXY] = 2
	};





	local start_port = Management::Controller::auto_assign_broker_start_port;

	local p = start_port as count;



	local ports_set: set[count];

	local node: Management::Node;


	for ( inst in config$instances )
		{
		if ( inst?$listen_port )
			add ports_set[inst$listen_port as count];
		}


	for ( node in config$nodes )
		{
		if ( node?$p )
			{
			add ports_set[node$p as count];
			add new_nodes[node];
			}
		}


	for ( node in config$nodes )
		{
		if ( node$role !in roles )
			add new_nodes[node];
		}


	local nodes: vector of Management::Node;

	for ( node in config$nodes )
		{
		if ( node?$p )
			next;
		if ( node$role !in roles )
			next;
		nodes += node;
		}

	sort(nodes, function [roles] (n1: Management::Node, n2: Management::Node): int
		{ return config_nodes_compare(n1, n2, roles); });

	for ( i in nodes )
		{
		node = nodes[i];


		while ( p in ports_set )
			++p;

		node$p = count_to_port(p, tcp);
		add new_nodes[node];
		add ports_set[p];


		++p;
		}

	config$nodes = new_nodes;
	}

function config_assign_metrics_ports(config: Management::Configuration)
	{

	local new_nodes: set[Management::Node];


	local roles: table[Supervisor::ClusterRole] of count = {
		[Supervisor::MANAGER] = 0,
		[Supervisor::LOGGER] = 1,
		[Supervisor::PROXY] = 2,
		[Supervisor::WORKER] = 3,
	};

	local instance_metrics_start_port: table[addr] of count;
	local instance_ports_set: table[addr] of set[count];
	local instance_addr_lookup: table[string] of addr;
	local node: Management::Node;
	local node_addr: addr;


	for ( inst in config$instances )
		{

		instance_addr_lookup[inst$name] = inst$host;

		instance_metrics_start_port[inst$host] = Management::Controller::auto_assign_metrics_start_port as count;
		instance_ports_set[inst$host] = {};
		if ( inst?$listen_port )
			add instance_ports_set[inst$host][inst$listen_port as count];
		}



	for ( node in config$nodes )
		{
		node_addr = instance_addr_lookup[node$instance];
		if ( node?$p )
			add instance_ports_set[node_addr][node$p as count];
		if ( node?$metrics_port )
			{
			add instance_ports_set[node_addr][node$metrics_port as count];
			add new_nodes[node];
			}
		}




	for ( node in config$nodes )
		{
		if ( node$role !in roles )
			add new_nodes[node];
		}


	local nodes: vector of Management::Node;

	for ( node in config$nodes )
		{
		if ( node?$metrics_port )
			next;
		if ( node$role !in roles )
			next;
		nodes += node;
		}

	sort(nodes, function [roles] (n1: Management::Node, n2: Management::Node): int
		{ return config_nodes_compare(n1, n2, roles); });

	for ( i in nodes )
		{
		node = nodes[i];
		node_addr = instance_addr_lookup[node$instance];


		while ( instance_metrics_start_port[node_addr] in instance_ports_set[node_addr] )
			++instance_metrics_start_port[node_addr];

		node$metrics_port = count_to_port(instance_metrics_start_port[node_addr], tcp);
		add new_nodes[node];
		add instance_ports_set[node_addr][instance_metrics_start_port[node_addr]];


		++instance_metrics_start_port[node_addr];
		}

	config$nodes = new_nodes;
	}

function config_validate(config: Management::Configuration,
    req: Management::Request::Request): bool
	{
	local errors: Management::ResultVec;
	local make_error = function(reqid: string, error: string): Management::Result
		{ return Management::Result($reqid=reqid, $success=F, $error=error); };












	local inst_names: set[string];
	local node_names: set[string];
	local inst_names_done: set[string];
	local node_names_done: set[string];

	for ( inst in config$instances )
		{
		if ( inst$name !in inst_names )
			{
			add inst_names[inst$name];
			next;
			}

		if ( inst$name !in inst_names_done )
			{
			errors += make_error(req$id, fmt("multiple instances named '%s'", inst$name));
			add inst_names_done[inst$name];
			}
		}

	for ( node in config$nodes )
		{
		if ( node$name !in node_names )
			{
			add node_names[node$name];
			next;
			}

		if ( node$name !in node_names_done )
			{
			errors += make_error(req$id, fmt("multiple nodes named '%s'", node$name));
			add node_names_done[node$name];
			}
		}


	local both_names = inst_names & node_names;

	if ( |both_names| > 0 )
		errors += make_error(req$id, fmt("node and instance names collide: %s",
		    join_string_vec(Management::Util::set_to_vector(both_names), ", ")));



	for ( node in config$nodes )
		{
		if ( node$instance !in inst_names )
			errors += make_error(req$id, fmt("node '%s' has undeclared instance name '%s'",
			    node$name, node$instance));
		}




	local inst_ports: table[string] of set[port];
	local node_ports: table[string] of set[port];
	local node_ports_done: table[string] of set[port];

	for ( inst in config$instances )
		{
		if ( ! inst?$listen_port )
			next;
		if ( inst$name !in inst_ports )
			inst_ports[inst$name] = set();
		add inst_ports[inst$name][inst$listen_port];
		}

	for ( node in config$nodes )
		{
		if ( node$instance !in node_ports )
			node_ports[node$instance] = set();
		if ( node$instance !in node_ports_done )
			node_ports_done[node$instance] = set();

		if ( ! node?$p )
			next;

		if ( node$instance in inst_ports && node$p in inst_ports[node$instance] )
			errors += make_error(req$id, fmt("node '%s' port %s conflicts with agent port on instance '%s'",
			    node$name, node$p, node$instance));





		if ( node$p == Management::Controller::network_info()$bound_port )
			errors += make_error(req$id, fmt("node '%s' port %s conflicts with controller port",
			    node$name, node$p));

		if ( node$p !in node_ports[node$instance] )
			{
			add node_ports[node$instance][node$p];
			next;
			}

		if ( node$p !in node_ports_done[node$instance] )
			{
			errors += make_error(req$id, fmt("multiple nodes on instance '%s' using port %s",
			    node$instance, node$p));
			add node_ports_done[node$instance][node$p];
			}
		}





	local nodes: vector of string;
	local nodes_str: string;

	if ( ! Management::Controller::auto_assign_broker_ports )
		{
		nodes = config_nodes_lacking_broker_ports(config);

		if ( |nodes| > 0 )
			{
			nodes_str = join_string_vec(nodes, ", ");
			errors += make_error(req$id, fmt("Broker port auto-assignment disabled but nodes %s lack ports", nodes_str));
			}
		}











	if ( |errors| == 0 )
		return T;



	sort(errors, function(r1: Management::Result, r2: Management::Result): int
		{ return strcmp(r1$error, r2$error); });

	for ( i in errors )
		req$results += errors[i];

	return F;
	}

function config_filter_nodes_by_name(config: Management::Configuration, nodes: set[string])
    : set[string]
	{
	local res: set[string];
	local cluster_nodes: set[string];

	for ( node in config$nodes )
		add cluster_nodes[node$name];

	return nodes & cluster_nodes;
	}

function find_endpoint(id: string): Broker::EndpointInfo
	{
	local peers = Broker::peers();

	for ( i in peers )
		{
		if ( peers[i]$peer$id == id )
			return peers[i]$peer;
		}


	return Broker::EndpointInfo($id="");
	}

function is_instance_connectivity_change(inst: Management::Instance): bool
	{


	if ( inst$name !in g_instances )
		return F;




	if ( inst$host != 0.0.0.0 && inst$host != g_instances[inst$name]$host )
		return T;



	if ( inst?$listen_port != g_instances[inst$name]?$listen_port )
		return T;


	if ( inst?$listen_port && g_instances[inst$name]?$listen_port &&
	     inst$listen_port != g_instances[inst$name]$listen_port )
		return T;

	return F;
	}

function deploy(req: Management::Request::Request)
	{



	g_config_reqid_pending = req$id;








	local insts_current: set[string];
	local insts_new: set[string];



	local insts_to_drop: set[string];



	local insts_to_add: set[string];




	local insts_to_keep: set[string];


	local insts_to_peer: table[string] of Management::Instance;


	local inst_name: string;
	local inst: Management::Instance;

	for ( inst_name in g_instances )
		add insts_current[inst_name];
	for ( inst in g_configs[READY]$instances )
		add insts_new[inst$name];


	insts_to_drop = insts_current - insts_new;
	insts_to_add = insts_new - insts_current;
	insts_to_keep = insts_new & insts_current;

	for ( inst in g_configs[READY]$instances )
		{
		if ( inst$name in insts_to_add )
			{
			insts_to_peer[inst$name] = inst;
			next;
			}


		if ( inst$name !in insts_to_keep )
			next;

		if ( is_instance_connectivity_change(inst) )
			{



			add insts_to_drop[inst$name];
			add insts_to_add[inst$name];
			}
		}




	for ( inst_name in insts_to_drop )
		{
		Management::Log::debug(fmt("dropping instance %s", inst_name));
		drop_instance(g_instances[inst_name]);
		}
	for ( inst_name in insts_to_peer )
		{
		Management::Log::debug(fmt("adding instance %s", inst_name));
		add_instance(insts_to_peer[inst_name]);
		}






	if ( |insts_new| == 0 )
		{
		local config = req$deploy_state$config;
		g_configs[DEPLOYED] = config;
		g_config_reqid_pending = "";

		local res = Management::Result($reqid=req$id, $data=config$id);
		req$results += res;

		if ( ! req$deploy_state$is_internal )
			{
			Management::Log::info(fmt("tx Management::Controller::API::deploy_response %s",
			    Management::Request::to_string(req)));
			Broker::publish(Management::Controller::topic,
			    Management::Controller::API::deploy_response, req$id, req$results);
			}

		Management::Request::finish(req$id);
		return;
		}
	}

event Management::Controller::API::notify_agents_ready(instances: set[string])
	{
	local insts = Management::Util::set_to_vector(instances);
	local req: Management::Request::Request;

	Management::Log::info(fmt("rx Management::Controller::API:notify_agents_ready %s",
	    join_string_vec(insts, ", ")));





	if ( g_config_reqid_pending == "" && DEPLOYED in g_configs )
		{
		req = Management::Request::create();
		req$deploy_state = DeployState($config=g_configs[DEPLOYED], $is_internal=T);
		Management::Log::info(fmt("no deployment in progress, triggering via %s", req$id));
		deploy(req);
		}

	req = Management::Request::lookup(g_config_reqid_pending);



	if ( Management::Request::is_null(req) || ! req?$deploy_state )
		return;





	config_deploy_to_agents(req$deploy_state$config, req);
	}

event Management::Agent::API::notify_agent_hello(instance: string, id: string, connecting: bool, api_version: count)
	{
	Management::Log::info(fmt("rx Management::Agent::API::notify_agent_hello %s %s %s",
	    instance, id, connecting));



	if ( api_version != Management::Controller::API::version )
		{
		Management::Log::warning(
		    fmt("instance %s/%s has checked in with incompatible API version %s",
		        instance, id, api_version));

		if ( instance in g_instances )
			drop_instance(g_instances[instance]);
		if ( instance in g_instances_known )
			delete g_instances_known[instance];

		return;
		}

	local ei = find_endpoint(id);

	if ( ei$id == "" )
		{
		Management::Log::warning(fmt("notify_agent_hello from %s with unknown Broker ID %s",
		    instance, id));
		}

	if ( ! ei?$network )
		{
		Management::Log::warning(fmt("notify_agent_hello from %s lacks network state, Broker ID %s",
		    instance, id));
		}

	if ( ei$id != "" && ei?$network )
		{
		if ( instance !in g_instances_known )
			Management::Log::debug(fmt("instance %s newly checked in", instance));
		else
			Management::Log::debug(fmt("instance %s checked in again", instance));

		g_instances_by_id[id] = instance;
		g_instances_known[instance] = Management::Instance(
		    $name=instance, $host=ei$network$address as addr);

		if ( ! connecting )
			{

			g_instances_known[instance]$listen_port = ei$network$bound_port;
			}
		}

	if ( instance in g_instances && instance !in g_instances_ready )
		{


		local req = Management::Request::create();

		Management::Log::info(fmt("tx Management::Agent::API::agent_welcome_request %s to %s", req$id, instance));
		Broker::publish(Management::Agent::topic_prefix + "/" + instance,
		    Management::Agent::API::agent_welcome_request, req$id);
		}
	}

event Management::Agent::API::agent_welcome_response(reqid: string, result: Management::Result)
	{
	Management::Log::info(fmt("rx Management::Agent::API::agent_welcome_response %s", reqid));

	local req = Management::Request::lookup(reqid);

	if ( Management::Request::is_null(req) )
		return;

	Management::Request::finish(req$id);



	if ( ! result$success || result$instance !in g_instances )
		{
		Management::Log::info(fmt(
		    "tx Management::Agent::API::agent_standby_request to %s", result$instance));
		Broker::publish(Management::Agent::topic_prefix + "/" + result$instance,
		    Management::Agent::API::agent_standby_request, "");
		return;
		}

	add g_instances_ready[result$instance];
	Management::Log::info(fmt("instance %s ready", result$instance));

	check_instances_ready();
	}

event Management::Agent::API::notify_change(instance: string, n: Management::Node,
    old: Management::State, new: Management::State)
	{

	}

event Management::Agent::API::notify_error(instance: string, msg: string, node: string)
	{

	}

event Management::Agent::API::notify_log(instance: string, msg: string, node: string)
	{

	}

event Management::Agent::API::deploy_response(reqid: string, results: Management::ResultVec)
	{
	Management::Log::info(fmt("rx Management::Agent::API::deploy_response %s %s",
	    reqid, Management::result_vec_to_string(results)));


	local areq = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(areq) )
		return;


	Management::Request::finish(areq$id);


	local req = Management::Request::lookup(areq$parent_id);
	if ( Management::Request::is_null(req) )
		return;


	for ( i in results )
		{

		if ( results[i]?$data )
			results[i]$data = results[i]$data as Management::NodeOutputs;

		req$results[|req$results|] = results[i];
		}



	if ( areq$id in req$deploy_state$requests )
		delete req$deploy_state$requests[areq$id];



	if ( |req$deploy_state$requests| > 0 )
		return;



	local config = req$deploy_state$config;
	g_configs[DEPLOYED] = config;
	g_config_reqid_pending = "";

	local res = Management::Result($reqid=req$id, $data=config$id);
	req$results += res;

	if ( ! req$deploy_state$is_internal )
		{
		Management::Log::info(fmt("tx Management::Controller::API::deploy_response %s",
		    Management::Request::to_string(req)));
		Broker::publish(Management::Controller::topic,
		    Management::Controller::API::deploy_response, req$id, req$results);
		}

	Management::Request::finish(req$id);
	}

event Management::Controller::API::stage_configuration_request(reqid: string, config: Management::Configuration)
	{
	Management::Log::info(fmt("rx Management::Controller::API::stage_configuration_request %s", reqid));

	local req = Management::Request::create(reqid);
	local res = Management::Result($reqid=req$id);
	local config_copy: Management::Configuration;

	if ( ! config_validate(config, req) )
		{
		Management::Request::finish(req$id);
		Management::Log::info(fmt("tx Management::Controller::API::stage_configuration_response %s",
		    Management::Request::to_string(req)));
		Broker::publish(Management::Controller::topic,
		    Management::Controller::API::stage_configuration_response, req$id, req$results);
		return;
		}

	g_configs[STAGED] = config;
	config_copy = copy(config);








	local instances: set[Management::Instance];

	for ( inst in config_copy$instances )
		{
		if ( inst$name in g_instances_known
		    && inst$host == 0.0.0.0
		    && g_instances_known[inst$name]$host != 0.0.0.0 )
			inst$host = g_instances_known[inst$name]$host;

		add instances[inst];
		}

	config_copy$instances = instances;

	if ( Management::Controller::auto_assign_broker_ports )
		config_assign_broker_ports(config_copy);
	if ( Management::Controller::auto_assign_metrics_ports )
		config_assign_metrics_ports(config_copy);

	g_configs[READY] = config_copy;


	res$data = config$id;
	req$results += res;

	Management::Log::info(fmt(
	    "tx Management::Controller::API::stage_configuration_response %s",
	    Management::result_to_string(res)));
	Broker::publish(Management::Controller::topic,
	    Management::Controller::API::stage_configuration_response, reqid, req$results);
	Management::Request::finish(req$id);
	}

event Management::Controller::API::get_configuration_request(reqid: string, deployed: bool)
	{
	Management::Log::info(fmt("rx Management::Controller::API::get_configuration_request %s", reqid));

	local res = Management::Result($reqid=reqid);
	local key = deployed ? DEPLOYED : STAGED;

	if ( key !in g_configs )
		{

		res$error = fmt("no %s configuration available", to_lower(sub(cat(key), /.+::/, "")));
		res$success = F;
		}
	else
		{
		res$data = g_configs[key];
		}

	Management::Log::info(fmt(
	    "tx Management::Controller::API::get_configuration_response %s",
	    Management::result_to_string(res)));
	Broker::publish(Management::Controller::topic,
	    Management::Controller::API::get_configuration_response, reqid, res);
	}

event Management::Controller::API::deploy_request(reqid: string)
	{
	local send_error_response = function(req: Management::Request::Request, error: string)
		{
		local res = Management::Result($reqid=req$id, $success=F, $error=error);
		req$results += res;

		Management::Log::info(fmt("tx Management::Controller::API::deploy_response %s",
		    Management::Request::to_string(req)));
		Broker::publish(Management::Controller::topic,
		    Management::Controller::API::deploy_response, req$id, req$results);
		};

	Management::Log::info(fmt("rx Management::Controller::API::deploy_request %s", reqid));

	local req = Management::Request::create(reqid);

	if ( READY !in g_configs )
		{
		send_error_response(req, "no configuration available to deploy");
		Management::Request::finish(req$id);
		return;
		}


	if ( g_config_reqid_pending != "" )
		{
		send_error_response(req,
		    fmt("earlier deployment %s still pending", g_config_reqid_pending));
		Management::Request::finish(req$id);
		return;
		}

	req$deploy_state = DeployState($config = g_configs[READY]);
	deploy(req);




	check_instances_ready();
	}

event Management::Controller::API::get_instances_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Controller::API::get_instances_request %s", reqid));

	local res = Management::Result($reqid = reqid);
	local inst_names: vector of string;
	local insts: vector of Management::Instance;

	for ( inst in g_instances_known )
		inst_names += inst;

	sort(inst_names, strcmp);

	for ( i in inst_names )
		insts += g_instances_known[inst_names[i]];

	res$data = insts;

	Management::Log::info(fmt("tx Management::Controller::API::get_instances_response %s", reqid));
	Broker::publish(Management::Controller::topic,
	    Management::Controller::API::get_instances_response, reqid, res);
	}

event Management::Agent::API::get_nodes_response(reqid: string, result: Management::Result)
	{
	Management::Log::info(fmt("rx Management::Agent::API::get_nodes_response %s", reqid));


	local areq = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(areq) )
		return;


	Management::Request::finish(areq$id);


	local req = Management::Request::lookup(areq$parent_id);
	if ( Management::Request::is_null(req) )
		return;







	result$data = result$data as Management::NodeStatusVec;


	req$results[|req$results|] = result;



	if ( areq$id in req$get_nodes_state$requests )
		delete req$get_nodes_state$requests[areq$id];




	if ( |req$get_nodes_state$requests| > 0 )
		return;

	Management::Log::info(fmt("tx Management::Controller::API::get_nodes_response %s",
	    Management::Request::to_string(req)));
	Broker::publish(Management::Controller::topic,
	    Management::Controller::API::get_nodes_response, req$id, req$results);
	Management::Request::finish(req$id);
	}

event Management::Controller::API::get_nodes_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Controller::API::get_nodes_request %s", reqid));


	if ( |g_instances_known| == 0 )
		{
		Management::Log::info(fmt("tx Management::Controller::API::get_nodes_response %s", reqid));
		local res = Management::Result($reqid=reqid, $success=F,
		    $error="no instances connected");
		Broker::publish(Management::Controller::topic,
		    Management::Controller::API::get_nodes_response, reqid, vector(res));
		return;
		}

	local req = Management::Request::create(reqid);
	req$get_nodes_state = GetNodesState();

	for ( name in g_instances_known )
		{
		local agent_topic = Management::Agent::topic_prefix + "/" + name;
		local areq = Management::Request::create();

		areq$parent_id = req$id;
		add req$get_nodes_state$requests[areq$id];

		Management::Log::info(fmt("tx Management::Agent::API::get_nodes_request %s to %s", areq$id, name));
		Broker::publish(agent_topic, Management::Agent::API::get_nodes_request, areq$id);
		}
	}

event Management::Agent::API::node_dispatch_response(reqid: string, results: Management::ResultVec)
	{
	Management::Log::info(fmt("rx Management::Agent::API::node_dispatch_response %s", reqid));


	local areq = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(areq) )
		return;


	Management::Request::finish(areq$id);


	local req = Management::Request::lookup(areq$parent_id);
	if ( Management::Request::is_null(req) )
		return;


	for ( i in results )
		{


		switch req$node_dispatch_state$action[0]
			{
			case "get_id_value":
				if ( results[i]?$data )
					results[i]$data = results[i]$data as string;
				break;
			default:
				Management::Log::error(fmt("unexpected dispatch command %s",
				    req$node_dispatch_state$action[0]));
				break;
			}

		req$results[|req$results|] = results[i];
		}


	if ( areq$id in req$node_dispatch_state$requests )
		delete req$node_dispatch_state$requests[areq$id];




	if ( |req$node_dispatch_state$requests| > 0 )
		return;


	switch req$node_dispatch_state$action[0]
		{
		case "get_id_value":
			Management::Log::info(fmt(
			    "tx Management::Controller::API::get_id_value_response %s",
			    Management::Request::to_string(req)));
			Broker::publish(Management::Controller::topic,
			    Management::Controller::API::get_id_value_response,
			    req$id, req$results);
			break;
		default:
			Management::Log::error(fmt("unexpected dispatch command %s",
			    req$node_dispatch_state$action[0]));
			break;
		}

	Management::Request::finish(req$id);
	}

event Management::Controller::API::get_id_value_request(reqid: string, id: string, nodes: set[string])
	{
	Management::Log::info(fmt("rx Management::Controller::API::get_id_value_request %s %s", reqid, id));

	local res: Management::Result;


	if ( |g_instances| == 0 )
		{
		Management::Log::info(fmt("tx Management::Controller::API::get_id_value_response %s", reqid));
		res = Management::Result($reqid=reqid, $success=F, $error="no cluster deployed");
		Broker::publish(Management::Controller::topic,
		    Management::Controller::API::get_id_value_response,
		    reqid, vector(res));
		return;
		}

	local action = vector("get_id_value", id);
	local req = Management::Request::create(reqid);
	req$node_dispatch_state = NodeDispatchState($action=action);

	local nodes_final: set[string];
	local node: string;




	if ( |nodes| > 0 )
		{

		nodes_final = config_filter_nodes_by_name(g_configs[DEPLOYED], nodes);

		local nodes_invalid = nodes - nodes_final;


		for ( node in nodes_invalid )
			{
			res = Management::Result($reqid=reqid, $node=node);
			res$success = F;
			res$error = "unknown cluster node";
			req$results += res;
			}


		if ( |nodes_final| == 0 )
			{
			Management::Log::info(fmt(
			    "tx Management::Controller::API::get_id_value_response %s",
			    Management::Request::to_string(req)));
			Broker::publish(Management::Controller::topic,
			    Management::Controller::API::get_id_value_response,
			    req$id, req$results);
			Management::Request::finish(req$id);
			return;
			}
		}


	for ( name in g_instances )
		{
		if ( name !in g_instances_ready )
			next;

		local agent_topic = Management::Agent::topic_prefix + "/" + name;
		local areq = Management::Request::create();

		areq$parent_id = req$id;
		add req$node_dispatch_state$requests[areq$id];

		Management::Log::info(fmt(
		    "tx Management::Agent::API::node_dispatch_request %s %s to %s",
		    areq$id, action, name));

		Broker::publish(agent_topic,
		    Management::Agent::API::node_dispatch_request,
		    areq$id, action, nodes_final);
		}
	}

event Management::Agent::API::restart_response(reqid: string, results: Management::ResultVec)
	{
	Management::Log::info(fmt("rx Management::Agent::API::restart_response %s", reqid));


	local areq = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(areq) )
		return;


	Management::Request::finish(areq$id);


	local req = Management::Request::lookup(areq$parent_id);
	if ( Management::Request::is_null(req) )
		return;


	for ( i in results )
		req$results += results[i];


	if ( areq$id in req$restart_state$requests )
		delete req$restart_state$requests[areq$id];




	if ( |req$restart_state$requests| > 0 )
		return;

	Management::Log::info(fmt(
	    "tx Management::Controller::API::restart_response %s",
	    Management::Request::to_string(req)));
	Broker::publish(Management::Controller::topic,
	    Management::Controller::API::restart_response,
	    req$id, req$results);
	Management::Request::finish(req$id);
	}

event Management::Controller::API::restart_request(reqid: string, nodes: set[string])
	{



	local send_error_response = function(req: Management::Request::Request, error: string)
		{
		local res = Management::Result($reqid=req$id, $success=F, $error=error);
		req$results += res;

		Management::Log::info(fmt("tx Management::Controller::API::restart_response %s",
		    Management::Request::to_string(req)));
		Broker::publish(Management::Controller::topic,
		    Management::Controller::API::restart_response, req$id, req$results);
		};

	Management::Log::info(fmt("rx Management::Controller::API::restart_request %s %s",
	    reqid, Management::Util::set_to_vector(nodes)));

	local res: Management::Result;
	local req = Management::Request::create(reqid);
	req$restart_state = RestartState();


	if ( |g_instances_known| == 0 )
		{
		send_error_response(req, "no instances connected");
		Management::Request::finish(reqid);
		return;
		}

	if ( DEPLOYED !in g_configs )
		{
		send_error_response(req, "no active cluster deployment");
		Management::Request::finish(reqid);
		return;
		}

	local nodes_final: set[string];
	local node: string;




	if ( |nodes| > 0 )
		{

		nodes_final = config_filter_nodes_by_name(g_configs[DEPLOYED], nodes);

		local nodes_invalid = nodes - nodes_final;


		for ( node in nodes_invalid )
			{
			res = Management::Result($reqid=reqid, $node=node);
			res$success = F;
			res$error = "unknown cluster node";
			req$results += res;
			}


		if ( |nodes_final| == 0 )
			{
			Management::Log::info(fmt(
			    "tx Management::Controller::API::restart_response %s",
			    Management::Request::to_string(req)));
			Broker::publish(Management::Controller::topic,
			    Management::Controller::API::restart_response,
			    req$id, req$results);
			Management::Request::finish(req$id);
			return;
			}
		}

	for ( name in g_instances )
		{
		if ( name !in g_instances_ready )
			next;

		local agent_topic = Management::Agent::topic_prefix + "/" + name;
		local areq = Management::Request::create();

		areq$parent_id = req$id;
		add req$restart_state$requests[areq$id];

		Management::Log::info(fmt(
		    "tx Management::Agent::API::restart_request %s to %s",
		    areq$id, name));

		Broker::publish(agent_topic,
		    Management::Agent::API::restart_request,
		    areq$id, nodes);
		}
	}

event Management::Request::request_expired(req: Management::Request::Request)
	{




	local res = Management::Result($reqid=req$id,
	    $success = F,
	    $error = "request timed out");

	Management::Log::info(fmt("request %s timed out", req$id));

	if ( req?$deploy_state )
		{

		g_config_reqid_pending = "";
		req$results += res;

		if ( ! req$deploy_state$is_internal )
			{
			Management::Log::info(fmt("tx Management::Controller::API::deploy_response %s",
			    Management::Request::to_string(req)));
			Broker::publish(Management::Controller::topic,
			    Management::Controller::API::deploy_response, req$id, req$results);
			}
		}

	if ( req?$get_nodes_state )
		{
		req$results += res;

		Management::Log::info(fmt("tx Management::Controller::API::get_nodes_response %s",
		    Management::Request::to_string(req)));
		Broker::publish(Management::Controller::topic,
		    Management::Controller::API::get_nodes_response, req$id, req$results);
		}

	if ( req?$node_dispatch_state )
		{
		req$results += res;

		switch req$node_dispatch_state$action[0]
			{
			case "get_id_value":
				Management::Log::info(fmt(
				    "tx Management::Controller::API::get_id_value_response %s",
				    Management::Request::to_string(req)));
				Broker::publish(Management::Controller::topic,
				    Management::Controller::API::get_id_value_response,
				    req$id, req$results);
				break;
			default:
				Management::Log::error(fmt("unexpected dispatch command %s",
				    req$node_dispatch_state$action[0]));
				break;
			}
		}

	if ( req?$restart_state )
		{
		req$results += res;

		Management::Log::info(fmt("tx Management::Controller::API::restart_response %s",
		    Management::Request::to_string(req)));
		Broker::publish(Management::Controller::topic,
		    Management::Controller::API::restart_response,
		    req$id, req$results);
		}

	if ( req?$test_state )
		{
		Management::Log::info(fmt("tx Management::Controller::API::test_timeout_response %s", req$id));
		Broker::publish(Management::Controller::topic,
		    Management::Controller::API::test_timeout_response, req$id, res);
		}
	}

event Management::Controller::API::test_timeout_request(reqid: string, with_state: bool)
	{
	Management::Log::info(fmt("rx Management::Controller::API::test_timeout_request %s %s", reqid, with_state));

	if ( with_state )
		{


		local req = Management::Request::create(reqid);
		req$test_state = TestState();
		}
	}

event Broker::peer_added(peer: Broker::EndpointInfo, msg: string)
	{
	Management::Log::debug(fmt("broker peer %s added: %s", peer, msg));
	}

event Broker::peer_lost(peer: Broker::EndpointInfo, msg: string)
	{
	Management::Log::debug(fmt("broker peer %s lost: %s", peer, msg));

	if ( peer$id in g_instances_by_id )
		{
		local instance = g_instances_by_id[peer$id];

		if ( instance in g_instances_known )
			delete g_instances_known[instance];
		if ( instance in g_instances_ready )
			delete g_instances_ready[instance];

		Management::Log::info(fmt("dropped state for instance %s", instance));
		delete g_instances_by_id[peer$id];
		}
	}

event zeek_init()
	{







	local broker_info = "no Broker port";
	local websocket_info = "no Websocket port";

	local cni = Management::Controller::network_info();

	if ( cni$bound_port != 0/unknown )
		{
		Broker::listen(cat(cni$address), cni$bound_port);
		broker_info = fmt("Broker port %s:%s", cni$address, cni$bound_port);
		}

	cni = Management::Controller::network_info_websocket();

	if ( cni$bound_port != 0/unknown )
		{
		local ws_opts = Cluster::WebSocketServerOptions($listen_addr=cni$address as addr,
		                                                $listen_port=cni$bound_port,
		                                                $tls_options=Management::Controller::tls_options_websocket);
		Cluster::listen_websocket(ws_opts);
		websocket_info = fmt("websocket port %s:%s", cni$address, cni$bound_port);
		}

	Broker::subscribe(Management::Agent::topic_prefix);
	Broker::subscribe(Management::Controller::topic);

	Management::Log::info(fmt("controller is live, Broker ID %s, %s, %s",
	    Broker::node_id(), broker_info, websocket_info));





	if ( DEPLOYED in g_configs )
		{
		local req = Management::Request::create();
		req$deploy_state = DeployState($config=g_configs[DEPLOYED], $is_internal=T);
		Management::Log::info(fmt("deploying persisted configuration %s, request %s",
		    g_configs[DEPLOYED]$id, req$id));
		deploy(req);
		}
	}
