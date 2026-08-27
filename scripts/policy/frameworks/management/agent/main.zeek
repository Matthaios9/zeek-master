




@load base/frameworks/broker
@load base/utils/paths

@load policy/frameworks/management
@load policy/frameworks/management/node/api
@load policy/frameworks/management/node/config
@load policy/frameworks/management/supervisor/api
@load policy/frameworks/management/supervisor/config

@load ./api
@load ./config

module Management::Agent::Runtime;




export {

	type SupervisorState: record {

		node: string &default="";

		status: Supervisor::Status &optional;

		restart_result: bool &optional;
	};


	type DeployState: record {


		nodes_pending: set[string];
	};



	type NodeDispatchState: record {


		action: vector of string;


		requests: set[string] &default=set();
	};


	type RestartState: record {


		requests: set[string] &default=set();
	};










	global trigger_log_archival: event(run_archival: bool &default=T);
}





redef record Management::Request::Request += {
	supervisor_state_agent: SupervisorState &optional;
	deploy_state_agent: DeployState &optional;
	node_dispatch_state_agent: NodeDispatchState &optional;
	restart_state_agent: RestartState &optional;
};


redef Management::role = Management::AGENT;



redef table_expire_interval = 2 sec;



redef Management::Request::timeout_interval = 5 sec;


global agent_topic: function(): string;


global supervisor_network_info: function(): Broker::NetworkInfo;



global supervisor_status: function(node: string): Management::Request::Request;



global supervisor_create: function(nc: Supervisor::NodeConfig): Management::Request::Request;



global supervisor_destroy: function(node: string): Management::Request::Request;



global supervisor_restart: function(node: string): Management::Request::Request;



global send_deploy_response: function(req: Management::Request::Request);



global deploy_request_finish: function(req: Management::Request::Request);



global restart_request_finish: function(req: Management::Request::Request);



global get_nodes_request_finish: function(req: Management::Request::Request);




global g_supervisor_peered = F;


global g_config: Management::Configuration;


global g_instances: table[string] of Management::Instance;


global g_nodes: table[string] of Management::Node;




global g_config_reqid_pending: string = "";




global g_cluster: table[string] of Supervisor::ClusterEndpoint;



global g_outputs: table[string] of Management::NodeOutputs;


function agent_topic(): string
	{
	local epi = Management::Agent::endpoint_info();
	return Management::Agent::topic_prefix + "/" + epi$id;
	}

function supervisor_network_info(): Broker::NetworkInfo
	{



	local address = Broker::default_listen_address;

	if ( address == "" )
		address = "127.0.0.1";

	return Broker::NetworkInfo($address=address, $bound_port=Broker::default_port);
	}

function send_deploy_response(req: Management::Request::Request)
	{
	local node: string;
	local res: Management::Result;


	for ( node in g_nodes )
		{
		res = Management::Result(
		    $reqid = req$id,
		    $instance = Management::Agent::get_name(),
		    $node = node);

		if ( node in req$deploy_state_agent$nodes_pending )
			{

			res$success = F;


			if ( node in g_outputs )
				res$data = g_outputs[node];
			}


		req$results[|req$results|] = res;
		}

	Management::Log::info(fmt("tx Management::Agent::API::deploy_response %s",
	    Management::result_vec_to_string(req$results)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::deploy_response, req$id, req$results);

	Management::Request::finish(req$id);

	if ( req$id == g_config_reqid_pending )
		g_config_reqid_pending = "";
	}

event Management::Agent::Runtime::trigger_log_archival(run_archival: bool)
	{


	if ( Management::Agent::archive_logs == F )
		return;

	local ival = Management::Agent::archive_interval;


	if ( ival == 0 secs )
		ival = Log::default_rotation_interval;






	if ( ival == 0 secs )
		return;

	local cmd = Management::Agent::archive_cmd;

	if ( cmd == "" )
		{
		cmd = join_string_vec(vector(Installation::root_dir, "bin"), "/");
		cmd = build_path_compressed(cmd, "zeek-archiver");
		}





	if ( run_archival && file_size(Log::default_rotation_dir) > 0 )
		{
		cmd = fmt("%s -1 %s %s",
		    cmd, Log::default_rotation_dir,
		    Management::Agent::archive_dir);

		Management::Log::info(fmt("triggering log archival via '%s'", cmd));
		system(cmd);
		}

	schedule ival { Management::Agent::Runtime::trigger_log_archival() };
	}

event Management::Supervisor::API::notify_node_exit(node: string, outputs: Management::NodeOutputs)
	{
	Management::Log::info(fmt("rx Management::Supervisor::API::notify_node_exit %s", node));

	if ( node in g_nodes )
		g_outputs[node] = outputs;
	}

event SupervisorControl::status_response(reqid: string, result: Supervisor::Status)
	{
	Management::Log::info(fmt("rx SupervisorControl::status_response %s", reqid));

	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;
	if ( ! req?$supervisor_state_agent )
		return;

	req$supervisor_state_agent$status = result;

	Management::Request::finish(reqid);
	}

event SupervisorControl::create_response(reqid: string, result: string)
	{
	Management::Log::info(fmt("rx SupervisorControl::create_response %s %s", reqid, result));

	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;
	if ( ! req?$supervisor_state_agent )
		return;

	local name = req$supervisor_state_agent$node;

	if ( |result| > 0 )
		{
		local msg = fmt("failed to create node %s: %s", name, result);
		Management::Log::error(msg);
		Broker::publish(agent_topic(),
		    Management::Agent::API::notify_error,
		    Management::Agent::get_name(), msg, name);
		}

	Management::Request::finish(reqid);
	}

event SupervisorControl::destroy_response(reqid: string, result: bool)
	{
	Management::Log::info(fmt("rx SupervisorControl::destroy_response %s %s", reqid, result));

	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;
	if ( ! req?$supervisor_state_agent )
		return;

	local name = req$supervisor_state_agent$node;

	if ( ! result )
		{
		local msg = fmt("failed to destroy node %s, %s", name, reqid);
		Management::Log::error(msg);
		Broker::publish(agent_topic(),
		    Management::Agent::API::notify_error,
		    Management::Agent::get_name(), msg, name);
		}

	Management::Request::finish(reqid);
	}

event SupervisorControl::restart_response(reqid: string, result: bool)
	{
	Management::Log::info(fmt("rx SupervisorControl::restart_response %s %s", reqid, result));

	local req = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(req) )
		return;
	if ( ! req?$supervisor_state_agent )
		return;

	local name = req$supervisor_state_agent$node;
	req$supervisor_state_agent$restart_result = result;

	if ( ! result )
		{
		local msg = fmt("failed to restart node %s", name);
		Management::Log::error(msg);
		Broker::publish(agent_topic(),
		    Management::Agent::API::notify_error,
		    Management::Agent::get_name(), msg, name);
		}

	Management::Request::finish(reqid);
	}

function supervisor_status(node: string): Management::Request::Request
	{
	local req = Management::Request::create();
	req$supervisor_state_agent = SupervisorState($node = node);

	Management::Log::info(fmt("tx SupervisorControl::status_request %s %s",
	    req$id, node == "" ? "<all>" : node));
	Broker::publish(SupervisorControl::topic_prefix,
	    SupervisorControl::status_request, req$id, node);

	return req;
	}

function supervisor_create(nc: Supervisor::NodeConfig): Management::Request::Request
	{
	local req = Management::Request::create();
	req$supervisor_state_agent = SupervisorState($node = nc$name);

	Management::Log::info(fmt("tx SupervisorControl::create_request %s %s",
	    req$id, nc$name));
	Broker::publish(SupervisorControl::topic_prefix,
	    SupervisorControl::create_request, req$id, nc);

	return req;
	}

function supervisor_destroy(node: string): Management::Request::Request
	{
	local req = Management::Request::create();
	req$supervisor_state_agent = SupervisorState($node = node);

	Management::Log::info(fmt("tx SupervisorControl::destroy_request %s %s",
	    req$id, node == "" ? "<all>" : node));
	Broker::publish(SupervisorControl::topic_prefix,
	    SupervisorControl::destroy_request, req$id, node);

	return req;
	}

function supervisor_restart(node: string): Management::Request::Request
	{
	local req = Management::Request::create();
	req$supervisor_state_agent = SupervisorState($node = node);

	Management::Log::info(fmt("tx SupervisorControl::restart_request %s %s",
	    req$id, node == "" ? "<all>" : node));
	Broker::publish(SupervisorControl::topic_prefix,
	    SupervisorControl::restart_request, req$id, node);

	return req;
	}

event Management::Agent::API::deploy_request(reqid: string, config: Management::Configuration, force: bool)
	{
	Management::Log::info(fmt("rx Management::Agent::API::deploy_request %s %s", reqid, config$id));

	local nodename: string;
	local node: Management::Node;
	local nc: Supervisor::NodeConfig;
	local res: Management::Result;


	if ( g_config$id == config$id && ! force )
		{
		res = Management::Result(
		    $reqid = reqid,
		    $instance = Management::Agent::get_name());

		Management::Log::info(fmt("already running config %s", config$id));
		Management::Log::info(fmt("tx Management::Agent::API::deploy_response %s",
		    Management::result_to_string(res)));
		Broker::publish(agent_topic(),
		    Management::Agent::API::deploy_response, reqid, vector(res));
		return;
		}

	local req = Management::Request::create(reqid);
	req$deploy_state_agent = DeployState();




	g_config = config;


	g_instances = table();
	for ( inst in config$instances )
		g_instances[inst$name] = inst;

	local sreq = supervisor_status("");
	sreq$parent_id = reqid;
	sreq$finish = deploy_request_finish;
	}

function deploy_request_finish(areq: Management::Request::Request)
	{
	local status = areq$supervisor_state_agent$status;

	for ( nodename in status$nodes )
		{
		if ( "ZEEK_MANAGEMENT_NODE" in status$nodes[nodename]$node$env )
			next;
		supervisor_destroy(status$nodes[nodename]$node$name);
		}

	local req = Management::Request::lookup(areq$parent_id);
	if ( Management::Request::is_null(req) )
		return;

	local res: Management::Result;
	local nc: Supervisor::NodeConfig;
	local node: Management::Node;


	g_nodes = table();
	g_cluster = table();


	if ( |g_config$nodes| == 0 )
		{
		g_config_reqid_pending = "";

		res = Management::Result(
		    $reqid = req$id,
		    $instance = Management::Agent::get_name());

		Management::Log::info(fmt("tx Management::Agent::API::deploy_response %s",
		    Management::result_to_string(res)));
		Broker::publish(agent_topic(),
		    Management::Agent::API::deploy_response, req$id, vector(res));
		return;
		}


	g_config_reqid_pending = req$id;

	for ( node in g_config$nodes )
		{

		if ( node$instance == Management::Agent::get_name() )
			{
			g_nodes[node$name] = node;
			add req$deploy_state_agent$nodes_pending[node$name];
			}





		local p = 0/unknown;

		if ( node?$p )
			p = node$p;




		local cep = Supervisor::ClusterEndpoint(
		    $role = node$role,
		    $host = g_instances[node$instance]$host,
		    $p = p);

		if ( node?$interface )
			cep$interface = node$interface;
		if ( node?$metrics_port )
			cep$metrics_port = node$metrics_port;

		g_cluster[node$name] = cep;
		}









	for ( nodename in g_nodes )
		{
		node = g_nodes[nodename];
		node$state = Management::PENDING;

		nc = Supervisor::NodeConfig($name=nodename);

		local statedir = build_path(Management::get_state_dir(), "nodes");

		if ( ! mkdir(statedir) )
			Management::Log::warning(fmt("could not create state dir '%s'", statedir));

		statedir = build_path(statedir, nodename);

		if ( ! mkdir(statedir) )
			Management::Log::warning(fmt("could not create node state dir '%s'", statedir));

		nc$directory = statedir;

		if ( node?$interface )
			nc$interface = node$interface;
		if ( node?$cpu_affinity )
			nc$cpu_affinity = node$cpu_affinity;
		if ( node?$scripts )
			nc$addl_user_scripts = node$scripts;
		if ( node?$env )
			nc$env = node$env;




		nc$addl_user_scripts += "policy/frameworks/management/node";









		nc$cluster = g_cluster;
		supervisor_create(nc);
		}





	}

event Management::Agent::API::get_nodes_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Agent::API::get_nodes_request %s", reqid));

	local req = Management::Request::create(reqid);

	local sreq = supervisor_status("");
	sreq$parent_id = reqid;
	sreq$finish = get_nodes_request_finish;
	}

function get_nodes_request_finish(areq: Management::Request::Request)
	{
	local req = Management::Request::lookup(areq$parent_id);
	if ( Management::Request::is_null(req) )
		return;

	local res = Management::Result($reqid=req$id,
	    $instance=Management::Agent::get_name());

	local node_statuses: Management::NodeStatusVec;

	for ( node in areq$supervisor_state_agent$status$nodes )
		{
		local sns = areq$supervisor_state_agent$status$nodes[node];
		local cns = Management::NodeStatus(
			    $node=node, $state=Management::PENDING);






		if ( node in sns$node$cluster )
			{
			local cep: Supervisor::ClusterEndpoint = sns$node$cluster[node];
			cns$cluster_role = cep$role;



			if ( node in g_nodes )
				cns$state = g_nodes[node]$state;



			if ( cep$p != 0/unknown )
				cns$p = cep$p;

			if ( cep?$metrics_port )
				cns$metrics_port = cep$metrics_port;
			}
		else
			{
			if ( "ZEEK_MANAGEMENT_NODE" in sns$node$env )
				{
				local role = sns$node$env["ZEEK_MANAGEMENT_NODE"];
				if ( role == "CONTROLLER" )
					{
					cns$mgmt_role = Management::CONTROLLER;




					cns$state = Management::RUNNING;


					cns$p = Management::Agent::endpoint_info()$network$bound_port;
					}
				else if ( role == "AGENT" )
					{
					cns$mgmt_role = Management::AGENT;


					cns$state = Management::RUNNING;



					if ( Management::Agent::controller$address == "0.0.0.0" )
						cns$p = Management::Agent::endpoint_info()$network$bound_port;
					}
				else
					Management::Log::warning(fmt(
					    "unexpected cluster management node type '%'", role));
				}
			}


		if ( sns?$pid )
			cns$pid = sns$pid;

		node_statuses += cns;
		}

	res$data = node_statuses;

	Management::Log::info(fmt("tx Management::Agent::API::get_nodes_response %s",
	    Management::result_to_string(res)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::get_nodes_response, req$id, res);
	Management::Request::finish(req$id);
	}

event Management::Node::API::node_dispatch_response(reqid: string, result: Management::Result)
	{
	local node = "unknown node";
	if ( result?$node )
		node = result$node;

	Management::Log::info(fmt("rx Management::Node::API::node_dispatch_response %s from %s", reqid, node));


	local nreq = Management::Request::lookup(reqid);
	if ( Management::Request::is_null(nreq) )
		return;


	local req = Management::Request::lookup(nreq$parent_id);
	if ( Management::Request::is_null(req) )
		return;




	if ( result?$node )
		{
		if ( result$node in req$node_dispatch_state_agent$requests )
			delete req$node_dispatch_state_agent$requests[result$node];
		else
			{

			Management::Log::debug(fmt("response %s not expected, ignoring", reqid));
			return;
			}
		}



	switch req$node_dispatch_state_agent$action[0]
		{
		case "get_id_value":
			if ( result?$data )
				result$data = result$data as string;
			break;
		default:
			Management::Log::error(fmt("unexpected dispatch command %s",
			    req$node_dispatch_state_agent$action[0]));
			break;
		}



	result$instance = Management::Agent::instance()$name;


	req$results[|req$results|] = result;




	if ( |req$node_dispatch_state_agent$requests| > 0 )
		return;


	Management::Request::finish(nreq$id);


	Management::Log::info(fmt("tx Management::Agent::API::node_dispatch_response %s",
	    Management::Request::to_string(req)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::node_dispatch_response, req$id, req$results);
	Management::Request::finish(req$id);
	}

event Management::Agent::API::node_dispatch_request(reqid: string, action: vector of string, nodes: set[string])
	{
	Management::Log::info(fmt("rx Management::Agent::API::node_dispatch_request %s %s %s",
	    reqid, action, Management::Util::set_to_vector(nodes)));

	local node: string;
	local cluster_nodes: set[string];
	local nodes_final: set[string];

	for ( node in g_nodes )
		add cluster_nodes[node];







	if ( |nodes| > 0 )
		{
		nodes_final = nodes & cluster_nodes;

		if ( |nodes_final| == 0 )
			{
			Management::Log::info(fmt(
			    "tx Management::Agent::API::node_dispatch_response %s, no node overlap",
			    reqid));
			Broker::publish(agent_topic(),
			    Management::Agent::API::node_dispatch_response, reqid, vector());
			return;
			}
		}
	else if ( |g_nodes| == 0 )
		{



		Management::Log::info(fmt(
		    "tx Management::Agent::API::node_dispatch_response %s, no nodes registered",
		    reqid));
		Broker::publish(agent_topic(),
		    Management::Agent::API::node_dispatch_response, reqid, vector());
		return;
		}
	else
		{

		nodes_final = cluster_nodes;
		}

	local res: Management::Result;
	local req = Management::Request::create(reqid);

	req$node_dispatch_state_agent = NodeDispatchState($action=action);




	for ( node in nodes_final )
		{
		if ( g_nodes[node]$state == Management::RUNNING )
			add req$node_dispatch_state_agent$requests[node];
		else
			{
			res = Management::Result($reqid=reqid,
			    $instance = Management::Agent::get_name(),
			    $success = F,
			    $error = fmt("cluster node %s not in running state", node),
			    $node=node);
			req$results += res;
			}
		}


	if ( |req$node_dispatch_state_agent$requests| == 0 )
		{
		Management::Log::info(fmt(
		    "tx Management::Agent::API::node_dispatch_response %s, no nodes running",
		    reqid));
		Broker::publish(agent_topic(),
		    Management::Agent::API::node_dispatch_response, reqid, req$results);
		Management::Request::finish(req$id);
		return;
		}




	local nreq = Management::Request::create();
	nreq$parent_id = reqid;

	Management::Log::info(fmt("tx Management::Node::API::node_dispatch_request %s %s", nreq$id, action));
	Broker::publish(Management::Node::node_topic,
	    Management::Node::API::node_dispatch_request, nreq$id, action, nodes);
	}

event Management::Agent::API::agent_welcome_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Agent::API::agent_welcome_request %s", reqid));

	local res = Management::Result(
	    $reqid = reqid,
	    $instance = Management::Agent::get_name());

	Management::Log::info(fmt("tx Management::Agent::API::agent_welcome_response %s",
	    Management::result_to_string(res)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::agent_welcome_response, reqid, res);
	}

event Management::Agent::API::agent_standby_request(reqid: string)
	{
	Management::Log::info(fmt("rx Management::Agent::API::agent_standby_request %s", reqid));






	event Management::Agent::API::deploy_request("", Management::Configuration());

	local res = Management::Result(
	    $reqid = reqid,
	    $instance = Management::Agent::get_name());

	Management::Log::info(fmt("tx Management::Agent::API::agent_standby_response %s",
	    Management::result_to_string(res)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::agent_standby_response, reqid, res);
	}

function restart_request_finish(sreq: Management::Request::Request)
	{





	local req = Management::Request::lookup(sreq$parent_id);
	if ( Management::Request::is_null(req) )
		return;

	local node = sreq$supervisor_state_agent$node;

	local res = Management::Result(
	    $reqid = req$id,
	    $instance = Management::Agent::get_name(),
	    $node = node);

	if ( ! sreq$supervisor_state_agent$restart_result )
		{
		res$success = F;
		res$error = fmt("could not restart node %s", node);
		}

	req$results += res;

	if ( node in req$restart_state_agent$requests )
		{
		delete req$restart_state_agent$requests[node];
		if ( |req$restart_state_agent$requests| > 0 )
			return;
		}

	Management::Log::info(fmt(
	    "tx Management::Agent::API::restart_response %s",
	    Management::Request::to_string(req)));
	Broker::publish(agent_topic(),
	    Management::Agent::API::restart_response,
	    req$id, req$results);
	Management::Request::finish(req$id);
	}

event Management::Agent::API::restart_request(reqid: string,  nodes: set[string])
	{



	Management::Log::info(fmt("rx Management::Agent::API::restart_request %s %s",
	    reqid, Management::Util::set_to_vector(nodes)));

	local node: string;
	local cluster_nodes: set[string];
	local nodes_final: set[string];

	for ( node in g_nodes )
		add cluster_nodes[node];







	if ( |nodes| > 0 )
		{
		nodes_final = nodes & cluster_nodes;

		if ( |nodes_final| == 0 )
			{
			Management::Log::info(fmt(
			    "tx Management::Agent::API::restart_response %s, no node overlap",
			    reqid));
			Broker::publish(agent_topic(),
			    Management::Agent::API::restart_response, reqid, vector());
			return;
			}
		}
	else if ( |g_nodes| == 0 )
		{



		Management::Log::info(fmt(
		    "tx Management::Agent::API::restart_response %s, no nodes registered",
		    reqid));
		Broker::publish(agent_topic(),
		    Management::Agent::API::restart_response, reqid, vector());
		return;
		}
	else
		{

		nodes_final = cluster_nodes;
		}

	local res: Management::Result;
	local req = Management::Request::create(reqid);

	req$restart_state_agent = RestartState();


	for ( node in nodes_final )
		add req$restart_state_agent$requests[node];




	for ( node in nodes_final )
		{
		local sreq = supervisor_restart(node);
		sreq$parent_id = reqid;
		sreq$finish = restart_request_finish;

		if ( node in g_nodes )
			g_nodes[node]$state = Management::PENDING;
		}
	}

event Management::Node::API::notify_node_hello(node: string)
	{
	Management::Log::info(fmt("rx Management::Node::API::notify_node_hello %s", node));


	if ( node in g_nodes )
		g_nodes[node]$state = Management::RUNNING;





	local req = Management::Request::lookup(g_config_reqid_pending);

	if ( Management::Request::is_null(req) || ! req?$deploy_state_agent )
		return;

	if ( node in req$deploy_state_agent$nodes_pending )
		{
		delete req$deploy_state_agent$nodes_pending[node];
		if ( |req$deploy_state_agent$nodes_pending| == 0 )
			send_deploy_response(req);
		}
	}

event Management::Request::request_expired(req: Management::Request::Request)
	{
	Management::Log::info(fmt("request %s timed out", req$id));

	local res = Management::Result($reqid=req$id,
	    $instance = Management::Agent::get_name(),
	    $success = F,
	    $error = "request timed out");

	req$results += res;

	if ( req?$deploy_state_agent )
		{
		send_deploy_response(req);

		g_config_reqid_pending = "";
		}

	if ( req?$restart_state_agent )
		{
		Management::Log::info(fmt("tx Management::Agent::API::restart_response %s",
		    Management::Request::to_string(req)));
		Broker::publish(agent_topic(),
		    Management::Agent::API::restart_response, req$id, req$results);
		}
	}

event Broker::peer_added(peer: Broker::EndpointInfo, msg: string)
	{
	Management::Log::debug(fmt("broker peer %s added: %s", peer, msg));

	local sni = supervisor_network_info();

	if ( peer$network$address == sni$address && peer$network$bound_port == sni$bound_port )
		g_supervisor_peered = T;






	if ( g_supervisor_peered == F )
		return;




	local epi = Management::Agent::endpoint_info();

	Broker::publish(agent_topic(),
	    Management::Agent::API::notify_agent_hello,
	    epi$id, Broker::node_id(),
	    Management::Agent::controller$address != "0.0.0.0",
	    Management::Agent::API::version);
	}

event zeek_init()
	{
	local epi = Management::Agent::endpoint_info();



	local sni = supervisor_network_info();
	Broker::peer(sni$address, sni$bound_port, Broker::default_listen_retry);



	Broker::subscribe(agent_topic());
	Broker::subscribe(SupervisorControl::topic_prefix);
	Broker::subscribe(Management::Node::node_topic);
	Broker::subscribe(Management::Supervisor::topic_prefix);


	if ( Management::Agent::controller$address != "0.0.0.0" )
		{

		Broker::peer(Management::Agent::controller$address,
		    Management::Agent::controller$bound_port,
		    Management::connect_retry);
		}



	Broker::listen(cat(epi$network$address), epi$network$bound_port);

	if ( Management::Agent::archive_logs )
		schedule 0 secs { Management::Agent::Runtime::trigger_log_archival(F) };

	Management::Log::info(fmt("agent is live, Broker ID %s", Broker::node_id()));
	}
